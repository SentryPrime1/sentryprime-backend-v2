// Image Processing Service
// Handles image downloading, caching, and basic processing

import fetch from 'node-fetch';
import crypto from 'crypto';
import sharp from 'sharp';

export class ImageProcessingService {
  constructor(database, config = {}) {
    this.db = database;
    this.config = {
      maxImageSize: config.maxImageSize || 10 * 1024 * 1024, // 10MB
      maxDimensions: config.maxDimensions || { width: 2048, height: 2048 },
      supportedFormats: config.supportedFormats || ['jpeg', 'jpg', 'png', 'gif', 'webp'],
      cacheExpiry: config.cacheExpiry || 7 * 24 * 60 * 60 * 1000, // 7 days
      downloadTimeout: config.downloadTimeout || 30000, // 30 seconds
      userAgent: config.userAgent || 'SentryPrime-AltTextAI/1.0',
      ...config
    };
  }

  /**
   * Download and cache an image
   * @param {string} imageUrl - URL of the image to download
   * @param {Object} options - Download options
   * @returns {Promise<Object>} Image information and data
   */
  async downloadAndCacheImage(imageUrl, options = {}) {
    try {
      console.log(`Downloading image: ${imageUrl}`);
      
      // Validate URL
      if (!this.isValidImageUrl(imageUrl)) {
        throw new Error('Invalid image URL');
      }
      
      // Check cache first
      const cached = await this.getCachedImage(imageUrl);
      if (cached && !this.isCacheExpired(cached)) {
        console.log(`Using cached image: ${imageUrl}`);
        return this.formatImageInfo(cached);
      }
      
      // Download image
      const imageData = await this.downloadImage(imageUrl, options);
      
      // Process image
      const processedImage = await this.processImage(imageData);
      
      // Cache image
      await this.cacheImage(imageUrl, processedImage);
      
      console.log(`Successfully processed image: ${imageUrl}`);
      return this.formatImageInfo(processedImage);
      
    } catch (error) {
      console.error(`Failed to download/process image ${imageUrl}:`, error);
      throw new Error(`Image processing failed: ${error.message}`);
    }
  }

  /**
   * Download image from URL
   * @private
   */
  async downloadImage(imageUrl, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.downloadTimeout);
    
    try {
      const response = await fetch(imageUrl, {
        method: 'GET',
        headers: {
          'User-Agent': this.config.userAgent,
          'Accept': 'image/*',
          'Accept-Encoding': 'gzip, deflate',
          ...options.headers
        },
        signal: controller.signal,
        follow: 5, // Follow up to 5 redirects
        size: this.config.maxImageSize
      });
      
      clearTimeout(timeout);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      // Check content type
      const contentType = response.headers.get('content-type') || '';
      if (!contentType.startsWith('image/')) {
        throw new Error(`Invalid content type: ${contentType}`);
      }
      
      // Check content length
      const contentLength = parseInt(response.headers.get('content-length') || '0');
      if (contentLength > this.config.maxImageSize) {
        throw new Error(`Image too large: ${contentLength} bytes`);
      }
      
      // Download image data
      const buffer = await response.buffer();
      
      return {
        url: imageUrl,
        data: buffer,
        contentType,
        size: buffer.length,
        downloadedAt: new Date()
      };
      
    } catch (error) {
      clearTimeout(timeout);
      
      if (error.name === 'AbortError') {
        throw new Error('Download timeout');
      }
      
      throw error;
    }
  }

  /**
   * Process image (resize, optimize, extract metadata)
   * @private
   */
  async processImage(imageData) {
    try {
      let sharpImage = sharp(imageData.data);
      
      // Get image metadata
      const metadata = await sharpImage.metadata();
      
      // Validate image format
      if (!this.config.supportedFormats.includes(metadata.format)) {
        throw new Error(`Unsupported image format: ${metadata.format}`);
      }
      
      // Check dimensions
      const { width, height } = metadata;
      const maxWidth = this.config.maxDimensions.width;
      const maxHeight = this.config.maxDimensions.height;
      
      let processedData = imageData.data;
      let processedWidth = width;
      let processedHeight = height;
      
      // Resize if too large
      if (width > maxWidth || height > maxHeight) {
        console.log(`Resizing image from ${width}x${height} to fit ${maxWidth}x${maxHeight}`);
        
        const resized = await sharpImage
          .resize(maxWidth, maxHeight, {
            fit: 'inside',
            withoutEnlargement: true
          })
          .jpeg({ quality: 85 }) // Convert to JPEG for smaller size
          .toBuffer();
        
        processedData = resized;
        
        // Get new dimensions
        const resizedMetadata = await sharp(resized).metadata();
        processedWidth = resizedMetadata.width;
        processedHeight = resizedMetadata.height;
      }
      
      // Extract additional metadata for AI processing
      const imageInfo = await this.extractImageFeatures(sharpImage, metadata);
      
      return {
        ...imageData,
        data: processedData,
        width: processedWidth,
        height: processedHeight,
        format: metadata.format,
        hasAlpha: metadata.hasAlpha,
        channels: metadata.channels,
        density: metadata.density,
        colorSpace: metadata.space,
        features: imageInfo,
        processedAt: new Date()
      };
      
    } catch (error) {
      console.error('Image processing failed:', error);
      throw new Error(`Image processing failed: ${error.message}`);
    }
  }

  /**
   * Extract image features for AI analysis
   * @private
   */
  async extractImageFeatures(sharpImage, metadata) {
    try {
      const features = {
        aspectRatio: metadata.width / metadata.height,
        isLandscape: metadata.width > metadata.height,
        isPortrait: metadata.height > metadata.width,
        isSquare: Math.abs(metadata.width - metadata.height) < 10,
        isLarge: metadata.width > 800 || metadata.height > 600,
        isSmall: metadata.width < 100 && metadata.height < 100,
        hasTransparency: metadata.hasAlpha,
        colorDepth: metadata.channels
      };
      
      // Get dominant colors (simplified)
      try {
        const stats = await sharpImage.stats();
        features.dominantColors = stats.channels.map(channel => ({
          mean: Math.round(channel.mean),
          std: Math.round(channel.std)
        }));
        
        // Determine if image is likely decorative based on simple heuristics
        features.likelyDecorative = this.isLikelyDecorative(features, metadata);
        
      } catch (statsError) {
        console.warn('Failed to extract color stats:', statsError.message);
      }
      
      return features;
      
    } catch (error) {
      console.warn('Failed to extract image features:', error.message);
      return {
        aspectRatio: metadata.width / metadata.height,
        isLandscape: metadata.width > metadata.height,
        isPortrait: metadata.height > metadata.width,
        isSquare: Math.abs(metadata.width - metadata.height) < 10
      };
    }
  }

  /**
   * Determine if image is likely decorative
   * @private
   */
  isLikelyDecorative(features, metadata) {
    // Simple heuristics for decorative images
    const decorativeIndicators = [
      features.isSmall && (features.aspectRatio > 3 || features.aspectRatio < 0.33), // Very wide or tall small images
      metadata.width < 50 && metadata.height < 50, // Very small images
      features.aspectRatio > 5 || features.aspectRatio < 0.2, // Extreme aspect ratios
      metadata.width === metadata.height && metadata.width < 100 // Small square images
    ];
    
    return decorativeIndicators.filter(Boolean).length >= 2;
  }

  /**
   * Cache image in database
   * @private
   */
  async cacheImage(imageUrl, imageData) {
    try {
      if (!this.db) {
        console.warn('Database not available, skipping image cache');
        return;
      }
      
      await this.db.cacheImage(
        imageUrl,
        imageData.data,
        imageData.contentType,
        imageData.width,
        imageData.height,
        {
          features: imageData.features,
          format: imageData.format,
          processedAt: imageData.processedAt
        }
      );
      
    } catch (error) {
      console.warn('Failed to cache image:', error.message);
      // Don't throw error, caching is optional
    }
  }

  /**
   * Get cached image from database
   * @private
   */
  async getCachedImage(imageUrl) {
    try {
      if (!this.db) {
        return null;
      }
      
      return await this.db.getCachedImage(imageUrl);
      
    } catch (error) {
      console.warn('Failed to get cached image:', error.message);
      return null;
    }
  }

  /**
   * Check if cached image is expired
   * @private
   */
  isCacheExpired(cachedImage) {
    if (!cachedImage.accessed_at) {
      return true;
    }
    
    const accessedAt = new Date(cachedImage.accessed_at);
    const expiryTime = new Date(accessedAt.getTime() + this.config.cacheExpiry);
    
    return new Date() > expiryTime;
  }

  /**
   * Format image information for API response
   * @private
   */
  formatImageInfo(imageData) {
    return {
      url: imageData.url || imageData.image_url,
      width: imageData.width,
      height: imageData.height,
      format: imageData.format || imageData.content_type?.split('/')[1],
      size: imageData.size || imageData.file_size,
      aspectRatio: imageData.width / imageData.height,
      features: imageData.features || (imageData.alt_suggestions ? JSON.parse(imageData.alt_suggestions) : {}),
      cached: !!imageData.accessed_at,
      processedAt: imageData.processedAt || imageData.created_at
    };
  }

  /**
   * Validate image URL
   * @private
   */
  isValidImageUrl(url) {
    try {
      const parsed = new URL(url);
      
      // Only allow HTTP/HTTPS
      if (!['http:', 'https:'].includes(parsed.protocol )) {
        return false;
      }
      
      // Check for common image extensions
      const pathname = parsed.pathname.toLowerCase();
      const imageExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg'];
      const hasImageExtension = imageExtensions.some(ext => pathname.endsWith(ext));
      
      // Allow URLs without extensions (might be dynamic images)
      return true;
      
    } catch (error) {
      return false;
    }
  }

  /**
   * Clean up expired cache entries
   */
  async cleanupCache() {
    try {
      if (!this.db) {
        return { deleted: 0 };
      }
      
      const expiryDays = Math.ceil(this.config.cacheExpiry / (24 * 60 * 60 * 1000));
      const deletedCount = await this.db.cleanupImageCache(expiryDays);
      
      console.log(`Cleaned up ${deletedCount} expired cache entries`);
      
      return { deleted: deletedCount };
      
    } catch (error) {
      console.error('Cache cleanup failed:', error);
      throw error;
    }
  }

  /**
   * Get cache statistics
   */
  async getCacheStats() {
    try {
      if (!this.db) {
        return { available: false };
      }
      
      // This would require additional database queries
      // For now, return basic info
      return {
        available: true,
        maxSize: this.config.maxImageSize,
        maxDimensions: this.config.maxDimensions,
        supportedFormats: this.config.supportedFormats,
        cacheExpiry: this.config.cacheExpiry
      };
      
    } catch (error) {
      console.error('Failed to get cache stats:', error);
      return { available: false, error: error.message };
    }
  }

  /**
   * Get service health status
   */
  async getHealthStatus() {
    try {
      // Test image processing capability
      const testBuffer = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');
      await sharp(testBuffer).metadata();
      
      return {
        status: 'healthy',
        capabilities: {
          sharp: true,
          fetch: true,
          cache: !!this.db
        },
        config: {
          maxImageSize: this.config.maxImageSize,
          maxDimensions: this.config.maxDimensions,
          supportedFormats: this.config.supportedFormats
        }
      };
      
    } catch (error) {
      return {
        status: 'unhealthy',
        error: error.message
      };
    }
  }
}
