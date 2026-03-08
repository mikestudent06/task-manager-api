import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { LoginDto, RegisterDto, TokenPair, VerifyOtpDto } from './auth.dto';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { verifyToken } from './utils/jwt.util';
import { generateOtp } from './utils/otp.util';
import { MailService } from 'src/mail/mail.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
    private mailService: MailService,
  ) {}

  async register(dto: RegisterDto): Promise<void> {
    // note: no token return anymore
    this.logger.log(`Registration attempt for email: ${dto.email}`);

    const userExists = await this.prisma.user.findUnique({
      where: { email: dto.email.toLowerCase() },
    });

    if (userExists) {
      this.logger.warn(
        `Registration failed - email already exists: ${dto.email}`,
      );
      throw new ForbiddenException('Email already registered');
    }

    const hash = await bcrypt.hash(dto.password, 12);
    const otp = generateOtp();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min

    const user = await this.prisma.user.create({
      data: {
        email: dto.email.toLowerCase(),
        name: dto.name.trim(),
        password: hash,
        otp,
        otpExpires,
        isVerified: false,
      },
    });

    // Send OTP email (optional in dev when no SMTP is configured)
    try {
      await this.mailService.sendOtpEmail(user.email, otp);
      this.logger.log(`User registered and OTP sent: ${user.email}`);
    } catch (mailError) {
      if (process.env.NODE_ENV !== 'production') {
        this.logger.warn(
          `Mail not sent (no SMTP?). In dev, use this OTP for ${user.email}: ${otp}`,
        );
      } else {
        throw mailError;
      }
    }
  }

  async login(dto: LoginDto): Promise<TokenPair> {
    this.logger.log(`Login attempt for email: ${dto.email}`);

    const user = await this.prisma.user.findUnique({
      where: { email: dto.email.toLowerCase() },
    });

    const isValidUser =
      user && (await bcrypt.compare(dto.password, user.password));

    if (!isValidUser) {
      this.logger.warn(`Failed login attempt for email: ${dto.email}`);
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.isVerified) {
      this.logger.warn(
        `Login attempt before verification for user: ${dto.email}`,
      );
      throw new ForbiddenException(
        'Account not verified. Please verify your email before login.',
      );
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() },
    });

    this.logger.log(`Successful login for user: ${user.email}`);

    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    return tokens;
  }

  async logout(userId: string): Promise<void> {
    this.logger.log(`Logout attempt for user: ${userId}`);

    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshToken: null },
    });

    this.logger.log(`User logged out successfully: ${userId}`);
  }

  async refresh(refreshToken: string): Promise<TokenPair> {
    if (!refreshToken) {
      throw new UnauthorizedException('No refresh token provided');
    }

    const payload = verifyToken<{ sub: string; email: string }>(
      refreshToken,
      this.config.get('JWT_REFRESH_SECRET') as string,
      this.jwt,
    );

    if (!payload.sub) {
      throw new UnauthorizedException('Invalid token structure');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
    });

    if (!user || !user.refreshToken || !user.isActive) {
      throw new ForbiddenException('Access Denied');
    }

    const tokenMatches = await bcrypt.compare(refreshToken, user.refreshToken);
    if (!tokenMatches) {
      // Security measure: clear all refresh tokens if mismatch
      await this.prisma.user.update({
        where: { id: user.id },
        data: { refreshToken: null },
      });
      this.logger.warn(`Refresh token mismatch for user: ${user.id}`);
      throw new ForbiddenException('Access Denied');
    }

    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    this.logger.log(`Token refreshed for user: ${user.id}`);

    return tokens;
  }

  async verifyOtpAndLogin(otp: string, email: string): Promise<TokenPair> {
    this.logger.log(`OTP verification attempt for email: ${email}`);

    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user) {
      this.logger.warn(`OTP verification failed - user not found: ${email}`);
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.otp || !user.otpExpires) {
      this.logger.warn(
        `OTP verification failed - no active OTP for user: ${email}`,
      );
      throw new ForbiddenException(
        'No active OTP found. Please request a new one.',
      );
    }

    const now = new Date();
    const isOtpExpired = now > user.otpExpires;

    if (isOtpExpired) {
      this.logger.warn(
        `OTP verification failed - OTP expired for user: ${email}`,
      );
      // Clean up expired OTP
      await this.prisma.user.update({
        where: { id: user.id },
        data: { otp: null, otpExpires: null },
      });
      throw new ForbiddenException(
        'OTP has expired. Please request a new one.',
      );
    }

    const isOtpValid = user.otp === otp;

    if (!isOtpValid) {
      this.logger.warn(
        `OTP verification failed - invalid OTP for user: ${email}`,
      );
      throw new UnauthorizedException('Invalid OTP');
    }

    // OTP is valid and not expired - verify user and generate tokens
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        isVerified: true,
        otp: null,
        otpExpires: null,
        lastLoginAt: new Date(),
      },
    });

    this.logger.log(`User verified successfully: ${user.email}`);

    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);

    return tokens;
  }

  async resendOtp(email: string): Promise<void> {
    this.logger.log(`Resend OTP request for email: ${email}`);

    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user) {
      this.logger.warn(`Resend OTP failed - user not found: ${email}`);
      throw new UnauthorizedException('User not found');
    }

    if (user.isVerified) {
      this.logger.warn(`Resend OTP failed - user already verified: ${email}`);
      throw new ForbiddenException('Account already verified');
    }

    const otp = generateOtp();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await this.prisma.user.update({
      where: { id: user.id },
      data: { otp, otpExpires },
    });

    try {
      await this.mailService.sendOtpEmail(user.email, otp);
      this.logger.log(`OTP resent successfully: ${user.email}`);
    } catch (mailError) {
      if (process.env.NODE_ENV !== 'production') {
        this.logger.warn(
          `Mail not sent (no SMTP?). In dev, use this OTP for ${user.email}: ${otp}`,
        );
      } else {
        throw mailError;
      }
    }
  }

  async deactivateAccount(userId: string): Promise<void> {
    this.logger.log(`Deactivating account for user: ${userId}`);

    await this.prisma.user.update({
      where: { id: userId },
      data: {
        isActive: false,
        refreshToken: null,
      },
    });

    this.logger.log(`Account deactivated: ${userId}`);
  }

  async forgotPassword(email: string): Promise<void> {
    this.logger.log(`Forgot password request for email: ${email}`);

    const user = await this.prisma.user.findUnique({
      where: { email: email.toLowerCase() },
    });

    if (!user) {
      // Security: Don't reveal if email exists
      this.logger.warn(
        `Forgot password request for non-existent email: ${email}`,
      );
      return; // Always return success to prevent email enumeration
    }

    if (!user.isVerified) {
      this.logger.warn(`Forgot password for unverified user: ${email}`);
      throw new ForbiddenException('Please verify your email first');
    }

    const resetToken = generateOtp(32); // 32-character secure token
    const resetTokenExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        resetToken,
        resetTokenExpires,
      },
    });

    await this.mailService.sendPasswordResetEmail(user.email, resetToken);
    this.logger.log(`Password reset email sent: ${user.email}`);
  }

  async resetPassword(resetToken: string, newPassword: string): Promise<void> {
    this.logger.log(
      `Password reset attempt with token: ${resetToken.substring(0, 8)}...`,
    );

    const user = await this.prisma.user.findFirst({
      where: {
        resetToken,
        resetTokenExpires: { gt: new Date() },
      },
    });

    if (!user) {
      this.logger.warn(
        `Invalid or expired reset token: ${resetToken.substring(0, 8)}...`,
      );
      throw new UnauthorizedException('Invalid or expired reset token');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetToken: null,
        resetTokenExpires: null,
        refreshToken: null, // Force re-login everywhere
      },
    });

    this.logger.log(`Password reset successful for user: ${user.email}`);
  }

  private async generateTokens(
    userId: string,
    email: string,
  ): Promise<TokenPair> {
    const [access_token, refresh_token] = await Promise.all([
      this.jwt.signAsync(
        { sub: userId, email },
        {
          secret: this.config.get('JWT_SECRET'),
          expiresIn: this.config.get('JWT_ACCESS_EXPIRY', '15m'),
        },
      ),
      this.jwt.signAsync(
        { sub: userId, email },
        {
          secret: this.config.get('JWT_REFRESH_SECRET'),
          expiresIn: this.config.get('JWT_REFRESH_EXPIRY', '7d'),
        },
      ),
    ]);

    return { access_token, refresh_token };
  }

  private async updateRefreshToken(
    userId: string,
    token: string,
  ): Promise<void> {
    const hashed = await bcrypt.hash(token, 12);
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        refreshToken: hashed,
      },
    });
  }

  private get isProduction(): boolean {
    return this.config.get('NODE_ENV') === 'production';
  }
}
