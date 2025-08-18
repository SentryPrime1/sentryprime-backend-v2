// Alt Text AI Routes and Controllers
// RESTful API endpoints for Alt Text AI functionality

import express from 'express';
import { 
  authenticateToken, 
  altTextRateLimit,
  validateAltTextRequest,
  validateJobId,
  auditLogger,
  sanitizeInput
} from '../auth_middleware.js';
import { AltTextAIService } from '../services/AltTextAIService.js';

const router = express.Router();

// Initialize Alt Text AI service (will be injected by main app)
let altTextAIService = null;

// Middleware to ensure service is available
const requireService = (req, res, next) => {
  if (!altTextAIService) {
    return res.status(503).json({
      error: 'service_unavailable',
      message: 'Alt Text AI service is not available'
    });
  }
  next();
};

// Apply common middleware to all routes
router.use(sanitizeInput);
router.use(altTextRateLimit);

/**
 * Initialize Alt Text AI service
 * Called by main application during startup
 */
export const initializeAltTextAIRoutes = (database, config = {}) => {
  altTextAIService = new AltTextAIService(database, config);
  console.log('✅ Alt Text AI routes initialized');
};

/**
 * POST /api/alt-text-ai/jobs
 * Create a new Alt Text AI job
 */
router.post('/jobs', 
  authenticateToken,
  validateAltTextRequest,
  auditLogger('alt_text_job_create'),
  async (req, res) => {
    try {
      const { scan_id, website_url, options = {} } = req.body;
      const userId = req.userId;
      
      console.log(`Creating Alt Text AI job for user ${userId}, scan ${scan_id}`);
      
      // Create job using service
      const job = await altTextAIService.createJob(
        userId,
        scan_id,
        website_url,
        options
      );
      
      res.status(201).json({
        success: true,
        job
      });
      
    } catch (error) {
      console.error('Failed to create Alt Text AI job:', error);
      
      // Handle specific error types
      if (error.message.includes('not found') || error.message.includes('access denied')) {
        return res.status(404).json({
          error: 'scan_not_found',
          message: 'Scan not found or access denied'
        });
      }
      
      if (error.message.includes('No images found')) {
        return res.status(400).json({
          error: 'no_images_found',
          message: 'No images requiring alt text were found in the scan results'
        });
      }
      
      if (error.message.includes('Too many images')) {
        return res.status(400).json({
          error: 'too_many_images',
          message: error.message
        });
      }
      
      res.status(500).json({
        error: 'job_creation_failed',
        message: 'Failed to create Alt Text AI job'
      });
    }
  }
);

/**
 * GET /api/alt-text-ai/jobs/:jobId
 * Get job status and progress
 */
router.get('/jobs/:jobId',
  authenticateToken,
  validateJobId,
  auditLogger('alt_text_job_status'),
  async (req, res) => {
    try {
      const { jobId } = req.params;
      const userId = req.userId;
      
      const jobStatus = await altTextAIService.getJobStatus(jobId, userId);
      
      res.json({
        success: true,
        job: jobStatus
      });
      
    } catch (error) {
      console.error('Failed to get job status:', error);
      
      if (error.message.includes('not found')) {
        return res.status(404).json({
          error: 'job_not_found',
          message: 'Job not found'
        });
      }
      
      if (error.message.includes('access denied')) {
        return res.status(403).json({
          error: 'access_denied',
          message: 'Access denied'
        });
      }
      
      res.status(500).json({
        error: 'status_check_failed',
        message: 'Failed to check job status'
      });
    }
  }
);

/**
 * GET /api/alt-text-ai/jobs/:jobId/results
 * Get job results and alt text suggestions
 */
router.get('/jobs/:jobId/results',
  authenticateToken,
  validateJobId,
  auditLogger('alt_text_job_results'),
  async (req, res) => {
    try {
      const { jobId } = req.params;
      const userId = req.userId;
      
      const results = await altTextAIService.getJobResults(jobId, userId);
      
      res.json({
        success: true,
        results
      });
      
    } catch (error) {
      console.error('Failed to get job results:', error);
      
      if (error.message.includes('not found')) {
        return res.status(404).json({
          error: 'job_not_found',
          message: 'Job not found'
        });
      }
      
      if (error.message.includes('access denied')) {
        return res.status(403).json({
          error: 'access_denied',
          message: 'Access denied'
        });
      }
      
      if (error.message.includes('not completed')) {
        return res.status(202).json({
          error: 'job_not_ready',
          message: error.message
        });
      }
      
      res.status(500).json({
        error: 'results_fetch_failed',
        message: 'Failed to fetch job results'
      });
    }
  }
);

/**
 * DELETE /api/alt-text-ai/jobs/:jobId
 * Cancel a running job
 */
router.delete('/jobs/:jobId',
  authenticateToken,
  validateJobId,
  auditLogger('alt_text_job_cancel'),
  async (req, res) => {
    try {
      const { jobId } = req.params;
      const userId = req.userId;
      
      const result = await altTextAIService.cancelJob(jobId, userId);
      
      res.json({
        success: true,
        result
      });
      
    } catch (error) {
      console.error('Failed to cancel job:', error);
      
      if (error.message.includes('not found')) {
        return res.status(404).json({
          error: 'job_not_found',
          message: 'Job not found'
        });
      }
      
      if (error.message.includes('access denied')) {
        return res.status(403).json({
          error: 'access_denied',
          message: 'Access denied'
        });
      }
      
      if (error.message.includes('Cannot cancel')) {
        return res.status(400).json({
          error: 'cannot_cancel',
          message: error.message
        });
      }
      
      res.status(500).json({
        error: 'cancellation_failed',
        message: 'Failed to cancel job'
      });
    }
  }
);

/**
 * GET /api/alt-text-ai/jobs
 * List user's Alt Text AI jobs
 */
router.get('/jobs',
  authenticateToken,
  auditLogger('alt_text_jobs_list'),
  async (req, res) => {
    try {
      const userId = req.userId;
      const { limit = 20, status, scan_id } = req.query;
      
      // Get user's jobs from database
      const jobs = await altTextAIService.db.getUserAltTextJobs(
        userId, 
        Math.min(parseInt(limit), 100) // Cap at 100
      );
      
      // Filter by status if specified
      let filteredJobs = jobs;
      if (status) {
        filteredJobs = jobs.filter(job => job.status === status);
      }
      
      // Filter by scan_id if specified
      if (scan_id) {
        filteredJobs = filteredJobs.filter(job => job.scan_id === scan_id);
      }
      
      // Format response
      const formattedJobs = filteredJobs.map(job => ({
        jobId: job.job_id,
        status: job.status,
        websiteUrl: job.website_url,
        totalImages: job.total_images,
        processedImages: job.processed_images || 0,
        failedImages: job.failed_images || 0,
        progress: job.total_images > 0 ? Math.round((job.processed_images || 0) / job.total_images * 100) : 0,
        createdAt: job.created_at,
        updatedAt: job.updated_at,
        completedAt: job.completed_at,
        scanId: job.scan_id,
        websiteTitle: job.website_title
      }));
      
      res.json({
        success: true,
        jobs: formattedJobs,
        total: formattedJobs.length,
        filters: {
          status,
          scan_id,
          limit: parseInt(limit)
        }
      });
      
    } catch (error) {
      console.error('Failed to list jobs:', error);
      
      res.status(500).json({
        error: 'jobs_list_failed',
        message: 'Failed to retrieve jobs list'
      });
    }
  }
);

/**
 * POST /api/alt-text-ai/jobs/:jobId/suggestions/:suggestionId/select
 * Select a specific alt text suggestion
 */
router.post('/jobs/:jobId/suggestions/:suggestionId/select',
  authenticateToken,
  validateJobId,
  auditLogger('alt_text_suggestion_select'),
  async (req, res) => {
    try {
      const { jobId, suggestionId } = req.params;
      const { selectedSuggestion, userFeedback } = req.body;
      const userId = req.userId;
      
      // Verify job ownership
      const job = await altTextAIService.db.getAltTextJob(jobId);
      if (!job || job.user_id !== userId) {
        return res.status(404).json({
          error: 'job_not_found',
          message: 'Job not found or access denied'
        });
      }
      
      // Update suggestion selection
      const result = await altTextAIService.db.updateSuggestionSelection(
        suggestionId,
        selectedSuggestion,
        userFeedback
      );
      
      if (!result) {
        return res.status(404).json({
          error: 'suggestion_not_found',
          message: 'Suggestion not found'
        });
      }
      
      res.json({
        success: true,
        suggestion: result
      });
      
    } catch (error) {
      console.error('Failed to select suggestion:', error);
      
      res.status(500).json({
        error: 'suggestion_selection_failed',
        message: 'Failed to select suggestion'
      });
    }
  }
);

/**
 * GET /api/alt-text-ai/health
 * Service health check
 */
router.get('/health', async (req, res) => {
  try {
    if (!altTextAIService) {
      return res.status(503).json({
        status: 'unavailable',
        message: 'Alt Text AI service not initialized'
      });
    }
    
    const health = await altTextAIService.getHealthStatus();
    
    res.json({
      success: true,
      health
    });
    
  } catch (error) {
    console.error('Health check failed:', error);
    
    res.status(500).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

/**
 * GET /api/alt-text-ai/usage
 * Get API usage statistics (authenticated)
 */
router.get('/usage',
  authenticateToken,
  auditLogger('alt_text_usage_check'),
  async (req, res) => {
    try {
      const userId = req.userId;
      const { from_date, to_date } = req.query;
      
      // Get user's API usage from database
      const usage = await altTextAIService.db.getUserApiUsage(
        userId,
        from_date ? new Date(from_date) : null,
        to_date ? new Date(to_date) : null
      );
      
      // Get OpenAI service usage stats
      const openaiStats = altTextAIService.openaiService.getUsageStats();
      
      res.json({
        success: true,
        usage: {
          database: usage,
          openai: openaiStats,
          period: {
            from: from_date || 'all time',
            to: to_date || 'now'
          }
        }
      });
      
    } catch (error) {
      console.error('Failed to get usage stats:', error);
      
      res.status(500).json({
        error: 'usage_stats_failed',
        message: 'Failed to retrieve usage statistics'
      });
    }
  }
);

/**
 * GET /api/alt-text-ai/notifications
 * Get user notifications
 */
router.get('/notifications',
  authenticateToken,
  async (req, res) => {
    try {
      const userId = req.userId;
      const { unread_only, type, limit = 20 } = req.query;
      
      const options = {
        unreadOnly: unread_only === 'true',
        type,
        limit: Math.min(parseInt(limit), 100)
      };
      
      const notifications = altTextAIService.notificationService.getInAppNotifications(
        userId,
        options
      );
      
      const stats = altTextAIService.notificationService.getNotificationStats(userId);
      
      res.json({
        success: true,
        notifications,
        stats,
        filters: options
      });
      
    } catch (error) {
      console.error('Failed to get notifications:', error);
      
      res.status(500).json({
        error: 'notifications_failed',
        message: 'Failed to retrieve notifications'
      });
    }
  }
);

/**
 * POST /api/alt-text-ai/notifications/:notificationId/read
 * Mark notification as read
 */
router.post('/notifications/:notificationId/read',
  authenticateToken,
  async (req, res) => {
    try {
      const userId = req.userId;
      const { notificationId } = req.params;
      
      altTextAIService.notificationService.markNotificationAsRead(
        userId,
        notificationId
      );
      
      res.json({
        success: true,
        message: 'Notification marked as read'
      });
      
    } catch (error) {
      console.error('Failed to mark notification as read:', error);
      
      res.status(500).json({
        error: 'notification_update_failed',
        message: 'Failed to update notification'
      });
    }
  }
);

/**
 * POST /api/alt-text-ai/notifications/read-all
 * Mark all notifications as read
 */
router.post('/notifications/read-all',
  authenticateToken,
  async (req, res) => {
    try {
      const userId = req.userId;
      
      altTextAIService.notificationService.markAllNotificationsAsRead(userId);
      
      res.json({
        success: true,
        message: 'All notifications marked as read'
      });
      
    } catch (error) {
      console.error('Failed to mark all notifications as read:', error);
      
      res.status(500).json({
        error: 'notifications_update_failed',
        message: 'Failed to update notifications'
      });
    }
  }
);

/**
 * GET /api/alt-text-ai/estimate
 * Estimate cost and time for processing a scan
 */
router.get('/estimate',
  authenticateToken,
  async (req, res) => {
    try {
      const { scan_id } = req.query;
      const userId = req.userId;
      
      if (!scan_id) {
        return res.status(400).json({
          error: 'scan_id_required',
          message: 'scan_id parameter is required'
        });
      }
      
      // Get scan data
      const scan = await altTextAIService.db.getScanById(scan_id);
      if (!scan || scan.user_id !== userId) {
        return res.status(404).json({
          error: 'scan_not_found',
          message: 'Scan not found or access denied'
        });
      }
      
      // Extract images from scan (without processing)
      const images = await altTextAIService.extractImagesFromScan(scan);
      
      // Get cost estimate from OpenAI service
      const costEstimate = altTextAIService.openaiService.estimateCost(images.length);
      
      // Get time estimate from Alt Text AI service
      const timeEstimate = altTextAIService.estimateProcessingTime(images.length);
      
      res.json({
        success: true,
        estimate: {
          imageCount: images.length,
          cost: costEstimate,
          time: timeEstimate,
          scanId: scan_id
        }
      });
      
    } catch (error) {
      console.error('Failed to generate estimate:', error);
      
      res.status(500).json({
        error: 'estimate_failed',
        message: 'Failed to generate cost and time estimate'
      });
    }
  }
);

// Apply service requirement middleware to all routes except health
router.use((req, res, next) => {
  if (req.path === '/health') {
    return next();
  }
  return requireService(req, res, next);
});

export default router;
