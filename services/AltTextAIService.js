// Alt Text AI Service - Core Business Logic
// Orchestrates the entire Alt Text AI generation process

import { v4 as uuid } from 'uuid';
import { ImageProcessingService } from './ImageProcessingService.js';
import { OpenAIService } from './OpenAIService.js';
import { NotificationService } from './NotificationService.js';

export class AltTextAIService {
  constructor(database, config = {}) {
    this.db = database;
    this.config = {
      maxImagesPerJob: config.maxImagesPerJob || 100,
      maxConcurrentProcessing: config.maxConcurrentProcessing || 5,
      timeoutMs: config.timeoutMs || 300000, // 5 minutes
      retryAttempts: config.retryAttempts || 3,
      ...config
    };
    
    this.imageService = new ImageProcessingService(database, config.imageProcessing);
    this.openaiService = new OpenAIService(config.openai);
    this.notificationService = new NotificationService(config.notifications);
    
    // Track active jobs
    this.activeJobs = new Map();
  }

  /**
   * Create a new Alt Text AI job
   * @param {string} userId - User ID
   * @param {string} scanId - Scan ID
   * @param {string} websiteUrl - Website URL to process
   * @param {Object} options - Processing options
   * @returns {Promise<Object>} Job details
   */
  async createJob(userId, scanId, websiteUrl, options = {}) {
    try {
      console.log(`Creating Alt Text AI job for user ${userId}, scan ${scanId}`);
      
      // Validate inputs
      if (!userId || !scanId || !websiteUrl) {
        throw new Error('Missing required parameters: userId, scanId, websiteUrl');
      }
      
      // Check if user has permission to access this scan
      const scan = await this.db.getScanById(scanId);
      if (!scan || scan.user_id !== userId) {
        throw new Error('Scan not found or access denied');
      }
      
      // Extract images from scan data
      const images = await this.extractImagesFromScan(scan);
      
      if (images.length === 0) {
        throw new Error('No images found in scan results');
      }
      
      if (images.length > this.config.maxImagesPerJob) {
        throw new Error(`Too many images (${images.length}). Maximum allowed: ${this.config.maxImagesPerJob}`);
      }
      
      // Create job in database
      const job = await this.db.createAltTextJob(
        userId,
        scanId,
        websiteUrl,
        images.length
      );
      
      console.log(`Created Alt Text AI job ${job.job_id} with ${images.length} images`);
      
      // Start processing asynchronously
      this.processJobAsync(job.job_id, images, options);
      
      return {
        jobId: job.job_id,
        status: 'pending',
        totalImages: images.length,
        estimatedDuration: this.estimateProcessingTime(images.length),
        createdAt: job.created_at
      };
      
    } catch (error) {
      console.error('Failed to create Alt Text AI job:', error);
      throw error;
    }
  }

  /**
   * Get job status and progress
   * @param {string} jobId - Job ID
   * @param {string} userId - User ID (for authorization)
   * @returns {Promise<Object>} Job status
   */
  async getJobStatus(jobId, userId) {
    try {
      const job = await this.db.getAltTextJob(jobId);
      
      if (!job) {
        throw new Error('Job not found');
      }
      
      if (job.user_id !== userId) {
        throw new Error('Access denied');
      }
      
      const response = {
        jobId: job.job_id,
        status: job.status,
        totalImages: job.total_images,
        processedImages: job.processed_images || 0,
        failedImages: job.failed_images || 0,
        createdAt: job.created_at,
        updatedAt: job.updated_at,
        completedAt: job.completed_at
      };
      
      // Add progress percentage
      if (job.total_images > 0) {
        response.progress = Math.round((job.processed_images || 0) / job.total_images * 100);
      }
      
      // Add error message if failed
      if (job.status === 'failed' && job.error_message) {
        response.errorMessage = job.error_message;
      }
      
      // Add estimated time remaining for active jobs
      if (job.status === 'processing' && this.activeJobs.has(jobId)) {
        const activeJob = this.activeJobs.get(jobId);
        response.estimatedTimeRemaining = this.estimateRemainingTime(activeJob);
      }
      
      return response;
      
    } catch (error) {
      console.error('Failed to get job status:', error);
      throw error;
    }
  }

  /**
   * Get job results (suggestions)
   * @param {string} jobId - Job ID
   * @param {string} userId - User ID (for authorization)
   * @returns {Promise<Object>} Job results
   */
  async getJobResults(jobId, userId) {
    try {
      const job = await this.db.getAltTextJob(jobId);
      
      if (!job) {
        throw new Error('Job not found');
      }
      
      if (job.user_id !== userId) {
        throw new Error('Access denied');
      }
      
      if (job.status !== 'completed') {
        throw new Error(`Job is not completed. Current status: ${job.status}`);
      }
      
      // Get all suggestions for this job
      const suggestions = await this.db.getJobSuggestions(jobId);
      
      // Group suggestions by page
      const resultsByPage = {};
      
      for (const suggestion of suggestions) {
        const pageUrl = suggestion.page_url;
        
        if (!resultsByPage[pageUrl]) {
          resultsByPage[pageUrl] = {
            pageUrl,
            pageTitle: suggestion.page_title,
            images: []
          };
        }
        
        resultsByPage[pageUrl].images.push({
          id: suggestion.id,
          imageUrl: suggestion.image_url,
          selector: suggestion.image_selector,
          suggestions: [
            {
              text: suggestion.suggestion_1,
              confidence: suggestion.confidence_1,
              selected: suggestion.selected_suggestion === 1
            },
            {
              text: suggestion.suggestion_2,
              confidence: suggestion.confidence_2,
              selected: suggestion.selected_suggestion === 2
            },
            {
              text: suggestion.suggestion_3,
              confidence: suggestion.confidence_3,
              selected: suggestion.selected_suggestion === 3
            }
          ].filter(s => s.text), // Remove empty suggestions
          isDecorative: suggestion.is_decorative,
          userFeedback: suggestion.user_feedback
        });
      }
      
      return {
        jobId: job.job_id,
        status: job.status,
        websiteUrl: job.website_url,
        totalImages: job.total_images,
        processedImages: job.processed_images,
        failedImages: job.failed_images,
        completedAt: job.completed_at,
        results: Object.values(resultsByPage)
      };
      
    } catch (error) {
      console.error('Failed to get job results:', error);
      throw error;
    }
  }

  /**
   * Cancel a running job
   * @param {string} jobId - Job ID
   * @param {string} userId - User ID (for authorization)
   * @returns {Promise<Object>} Cancellation result
   */
  async cancelJob(jobId, userId) {
    try {
      const job = await this.db.getAltTextJob(jobId);
      
      if (!job) {
        throw new Error('Job not found');
      }
      
      if (job.user_id !== userId) {
        throw new Error('Access denied');
      }
      
      if (!['pending', 'processing'].includes(job.status)) {
        throw new Error(`Cannot cancel job with status: ${job.status}`);
      }
      
      // Mark job as cancelled in database
      await this.db.updateAltTextJobStatus(jobId, 'cancelled');
      
      // Stop active processing if running
      if (this.activeJobs.has(jobId)) {
        const activeJob = this.activeJobs.get(jobId);
        activeJob.cancelled = true;
        this.activeJobs.delete(jobId);
      }
      
      console.log(`Cancelled Alt Text AI job ${jobId}`);
      
      return {
        jobId,
        status: 'cancelled',
        message: 'Job cancelled successfully'
      };
      
    } catch (error) {
      console.error('Failed to cancel job:', error);
      throw error;
    }
  }

  /**
   * Process job asynchronously
   * @private
   */
  async processJobAsync(jobId, images, options = {}) {
    const startTime = Date.now();
    
    try {
      console.log(`Starting async processing for job ${jobId} with ${images.length} images`);
      
      // Track active job
      this.activeJobs.set(jobId, {
        startTime,
        totalImages: images.length,
        processedImages: 0,
        cancelled: false
      });
      
      // Update job status to processing
      await this.db.updateAltTextJobStatus(jobId, 'processing');
      
      // Process images in batches
      const batchSize = this.config.maxConcurrentProcessing;
      let processedCount = 0;
      let failedCount = 0;
      
      for (let i = 0; i < images.length; i += batchSize) {
        // Check if job was cancelled
        const activeJob = this.activeJobs.get(jobId);
        if (!activeJob || activeJob.cancelled) {
          console.log(`Job ${jobId} was cancelled, stopping processing`);
          return;
        }
        
        const batch = images.slice(i, i + batchSize);
        const batchPromises = batch.map(image => 
          this.processImage(jobId, image, options).catch(error => {
            console.error(`Failed to process image ${image.url}:`, error);
            return { success: false, error: error.message };
          })
        );
        
        const batchResults = await Promise.all(batchPromises);
        
        // Count successes and failures
        for (const result of batchResults) {
          if (result && result.success !== false) {
            processedCount++;
          } else {
            failedCount++;
          }
        }
        
        // Update progress
        activeJob.processedImages = processedCount;
        await this.db.updateAltTextJobStatus(
          jobId, 
          'processing', 
          processedCount, 
          failedCount
        );
        
        console.log(`Job ${jobId}: Processed ${processedCount}/${images.length} images`);
      }
      
      // Mark job as completed
      await this.db.updateAltTextJobStatus(jobId, 'completed', processedCount, failedCount);
      
      // Clean up active job tracking
      this.activeJobs.delete(jobId);
      
      const duration = Date.now() - startTime;
      console.log(`Job ${jobId} completed in ${duration}ms. Processed: ${processedCount}, Failed: ${failedCount}`);
      
      // Send completion notification
      await this.notificationService.sendJobCompletionNotification(jobId, {
        processedImages: processedCount,
        failedImages: failedCount,
        duration
      });
      
    } catch (error) {
      console.error(`Job ${jobId} failed:`, error);
      
      // Mark job as failed
      await this.db.updateAltTextJobStatus(
        jobId, 
        'failed', 
        null, 
        null, 
        error.message
      );
      
      // Clean up active job tracking
      this.activeJobs.delete(jobId);
      
      // Send failure notification
      await this.notificationService.sendJobFailureNotification(jobId, error);
    }
  }

  /**
   * Process a single image
   * @private
   */
  async processImage(jobId, imageData, options = {}) {
    try {
      // Download and cache image
      const imageInfo = await this.imageService.downloadAndCacheImage(imageData.url);
      
      // Generate alt text suggestions using OpenAI
      const suggestions = await this.openaiService.generateAltTextSuggestions(
        imageInfo,
        {
          pageContext: imageData.pageContext,
          pageTitle: imageData.pageTitle,
          existingAlt: imageData.currentAlt,
          ...options
        }
      );
      
      // Store suggestions in database
      const suggestionData = {
        imageUrl: imageData.url,
        selector: imageData.selector,
        pageUrl: imageData.pageUrl,
        pageTitle: imageData.pageTitle,
        pageContext: imageData.pageContext,
        suggestions: suggestions.suggestions,
        isDecorative: suggestions.isDecorative
      };
      
      await this.db.createAltTextSuggestion(jobId, suggestionData);
      
      return { success: true, suggestions };
      
    } catch (error) {
      console.error(`Failed to process image ${imageData.url}:`, error);
      throw error;
    }
  }

  /**
   * Extract images from scan data
   * @private
   */
  async extractImagesFromScan(scan) {
    const images = [];
    
    if (!scan.scan_data || !scan.scan_data.pages) {
      return images;
    }
    
    for (const page of scan.scan_data.pages) {
      // Look for images in violation data
      for (const violation of page.violations || []) {
        if (violation.id === 'image-alt' || violation.id === 'image-redundant-alt') {
          for (const node of violation.nodes || []) {
            // Extract image information from the HTML
            const imageInfo = this.extractImageFromNode(node, page);
            if (imageInfo) {
              images.push(imageInfo);
            }
          }
        }
      }
    }
    
    // Remove duplicates based on image URL
    const uniqueImages = images.filter((image, index, self) => 
      index === self.findIndex(i => i.url === image.url)
    );
    
    return uniqueImages;
  }

  /**
   * Extract image information from violation node
   * @private
   */
  extractImageFromNode(node, page) {
    try {
      // Parse HTML to extract image attributes
      const html = node.html || '';
      const srcMatch = html.match(/src=["']([^"']+)["']/i);
      const altMatch = html.match(/alt=["']([^"']*)["']/i);
      
      if (!srcMatch) {
        return null;
      }
      
      let imageUrl = srcMatch[1];
      
      // Convert relative URLs to absolute
      if (imageUrl.startsWith('/')) {
        const baseUrl = new URL(page.url);
        imageUrl = `${baseUrl.protocol}//${baseUrl.host}${imageUrl}`;
      } else if (imageUrl.startsWith('./') || !imageUrl.includes('://')) {
        imageUrl = new URL(imageUrl, page.url).toString();
      }
      
      return {
        url: imageUrl,
        currentAlt: altMatch ? altMatch[1] : '',
        selector: Array.isArray(node.target) ? node.target.join(' ') : node.target,
        pageUrl: page.url,
        pageTitle: page.title || '',
        pageContext: this.extractPageContext(page),
        html: html.slice(0, 500) // Limit HTML length
      };
      
    } catch (error) {
      console.error('Failed to extract image from node:', error);
      return null;
    }
  }

  /**
   * Extract relevant page context for AI processing
   * @private
   */
  extractPageContext(page) {
    // Extract meaningful context from page data
    const context = {
      title: page.title || '',
      url: page.url,
      headings: [],
      description: ''
    };
    
    // You could enhance this by parsing page content for headings, descriptions, etc.
    // For now, we'll use basic information
    
    return JSON.stringify(context);
  }

  /**
   * Estimate processing time based on number of images
   * @private
   */
  estimateProcessingTime(imageCount) {
    // Rough estimate: 2-5 seconds per image
    const avgTimePerImage = 3500; // milliseconds
    const estimatedMs = imageCount * avgTimePerImage;
    
    return {
      milliseconds: estimatedMs,
      seconds: Math.ceil(estimatedMs / 1000),
      minutes: Math.ceil(estimatedMs / 60000),
      humanReadable: this.formatDuration(estimatedMs)
    };
  }

  /**
   * Estimate remaining time for active job
   * @private
   */
  estimateRemainingTime(activeJob) {
    const elapsed = Date.now() - activeJob.startTime;
    const avgTimePerImage = elapsed / Math.max(activeJob.processedImages, 1);
    const remainingImages = activeJob.totalImages - activeJob.processedImages;
    const estimatedRemainingMs = remainingImages * avgTimePerImage;
    
    return {
      milliseconds: estimatedRemainingMs,
      seconds: Math.ceil(estimatedRemainingMs / 1000),
      humanReadable: this.formatDuration(estimatedRemainingMs)
    };
  }

  /**
   * Format duration in human-readable format
   * @private
   */
  formatDuration(milliseconds) {
    const seconds = Math.ceil(milliseconds / 1000);
    
    if (seconds < 60) {
      return `${seconds} second${seconds !== 1 ? 's' : ''}`;
    }
    
    const minutes = Math.ceil(seconds / 60);
    if (minutes < 60) {
      return `${minutes} minute${minutes !== 1 ? 's' : ''}`;
    }
    
    const hours = Math.ceil(minutes / 60);
    return `${hours} hour${hours !== 1 ? 's' : ''}`;
  }

  /**
   * Get service health status
   */
  async getHealthStatus() {
    const activeJobCount = this.activeJobs.size;
    
    return {
      status: 'healthy',
      activeJobs: activeJobCount,
      services: {
        imageProcessing: await this.imageService.getHealthStatus(),
        openai: await this.openaiService.getHealthStatus(),
        notifications: await this.notificationService.getHealthStatus()
      },
      config: {
        maxImagesPerJob: this.config.maxImagesPerJob,
        maxConcurrentProcessing: this.config.maxConcurrentProcessing,
        timeoutMs: this.config.timeoutMs
      }
    };
  }
}
