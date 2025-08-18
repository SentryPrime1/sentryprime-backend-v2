// Notification Service
// Handles user notifications for Alt Text AI job status updates

export class NotificationService {
  constructor(config = {}) {
    this.config = {
      enableEmail: config.enableEmail || false,
      enableWebhooks: config.enableWebhooks || false,
      enableInApp: config.enableInApp !== false, // Default to true
      emailProvider: config.emailProvider || 'console', // console, sendgrid, ses, etc.
      webhookUrl: config.webhookUrl,
      retryAttempts: config.retryAttempts || 3,
      retryDelay: config.retryDelay || 1000,
      ...config
    };
    
    // In-app notification storage (in production, use Redis or database)
    this.inAppNotifications = new Map();
    
    // Notification templates
    this.templates = {
      jobStarted: {
        subject: 'Alt Text AI Job Started',
        message: 'Your Alt Text AI job has started processing {totalImages} images.'
      },
      jobProgress: {
        subject: 'Alt Text AI Job Progress',
        message: 'Your Alt Text AI job is {progress}% complete ({processedImages}/{totalImages} images processed).'
      },
      jobCompleted: {
        subject: 'Alt Text AI Job Completed',
        message: 'Your Alt Text AI job has completed successfully! Processed {processedImages} images in {duration}.'
      },
      jobFailed: {
        subject: 'Alt Text AI Job Failed',
        message: 'Your Alt Text AI job encountered an error: {errorMessage}'
      },
      jobCancelled: {
        subject: 'Alt Text AI Job Cancelled',
        message: 'Your Alt Text AI job was cancelled as requested.'
      }
    };
  }

  /**
   * Send job started notification
   * @param {string} jobId - Job ID
   * @param {Object} jobData - Job information
   */
  async sendJobStartedNotification(jobId, jobData) {
    try {
      const notification = {
        type: 'job_started',
        jobId,
        title: this.templates.jobStarted.subject,
        message: this.interpolateTemplate(this.templates.jobStarted.message, jobData),
        data: jobData,
        timestamp: new Date().toISOString()
      };
      
      await this.sendNotification(notification, jobData.userId);
      
    } catch (error) {
      console.error('Failed to send job started notification:', error);
    }
  }

  /**
   * Send job progress notification
   * @param {string} jobId - Job ID
   * @param {Object} progressData - Progress information
   */
  async sendJobProgressNotification(jobId, progressData) {
    try {
      // Only send progress notifications at certain intervals (25%, 50%, 75%)
      const progress = progressData.progress || 0;
      const milestones = [25, 50, 75];
      
      if (!milestones.includes(progress)) {
        return; // Skip non-milestone progress updates
      }
      
      const notification = {
        type: 'job_progress',
        jobId,
        title: this.templates.jobProgress.subject,
        message: this.interpolateTemplate(this.templates.jobProgress.message, progressData),
        data: progressData,
        timestamp: new Date().toISOString()
      };
      
      await this.sendNotification(notification, progressData.userId);
      
    } catch (error) {
      console.error('Failed to send job progress notification:', error);
    }
  }

  /**
   * Send job completion notification
   * @param {string} jobId - Job ID
   * @param {Object} completionData - Completion information
   */
  async sendJobCompletionNotification(jobId, completionData) {
    try {
      const notification = {
        type: 'job_completed',
        jobId,
        title: this.templates.jobCompleted.subject,
        message: this.interpolateTemplate(this.templates.jobCompleted.message, {
          ...completionData,
          duration: this.formatDuration(completionData.duration)
        }),
        data: completionData,
        timestamp: new Date().toISOString(),
        actions: [
          {
            label: 'View Results',
            url: `/alt-text-ai/jobs/${jobId}/results`,
            type: 'primary'
          }
        ]
      };
      
      await this.sendNotification(notification, completionData.userId);
      
    } catch (error) {
      console.error('Failed to send job completion notification:', error);
    }
  }

  /**
   * Send job failure notification
   * @param {string} jobId - Job ID
   * @param {Error} error - Error that caused the failure
   */
  async sendJobFailureNotification(jobId, error, userId = null) {
    try {
      const notification = {
        type: 'job_failed',
        jobId,
        title: this.templates.jobFailed.subject,
        message: this.interpolateTemplate(this.templates.jobFailed.message, {
          errorMessage: error.message
        }),
        data: {
          error: error.message,
          timestamp: new Date().toISOString()
        },
        timestamp: new Date().toISOString(),
        severity: 'error',
        actions: [
          {
            label: 'Retry Job',
            url: `/alt-text-ai/jobs/${jobId}/retry`,
            type: 'secondary'
          },
          {
            label: 'Contact Support',
            url: '/support',
            type: 'link'
          }
        ]
      };
      
      await this.sendNotification(notification, userId);
      
    } catch (notificationError) {
      console.error('Failed to send job failure notification:', notificationError);
    }
  }

  /**
   * Send job cancellation notification
   * @param {string} jobId - Job ID
   * @param {string} userId - User ID
   */
  async sendJobCancellationNotification(jobId, userId) {
    try {
      const notification = {
        type: 'job_cancelled',
        jobId,
        title: this.templates.jobCancelled.subject,
        message: this.templates.jobCancelled.message,
        data: {
          jobId,
          timestamp: new Date().toISOString()
        },
        timestamp: new Date().toISOString()
      };
      
      await this.sendNotification(notification, userId);
      
    } catch (error) {
      console.error('Failed to send job cancellation notification:', error);
    }
  }

  /**
   * Send notification via all enabled channels
   * @private
   */
  async sendNotification(notification, userId) {
    const promises = [];
    
    // In-app notifications
    if (this.config.enableInApp) {
      promises.push(this.sendInAppNotification(notification, userId));
    }
    
    // Email notifications
    if (this.config.enableEmail) {
      promises.push(this.sendEmailNotification(notification, userId));
    }
    
    // Webhook notifications
    if (this.config.enableWebhooks && this.config.webhookUrl) {
      promises.push(this.sendWebhookNotification(notification, userId));
    }
    
    // Send all notifications concurrently
    const results = await Promise.allSettled(promises);
    
    // Log any failures
    results.forEach((result, index) => {
      if (result.status === 'rejected') {
        const channels = ['in-app', 'email', 'webhook'];
        console.error(`Failed to send ${channels[index]} notification:`, result.reason);
      }
    });
  }

  /**
   * Send in-app notification
   * @private
   */
  async sendInAppNotification(notification, userId) {
    try {
      if (!userId) {
        return;
      }
      
      // Store notification for user
      if (!this.inAppNotifications.has(userId)) {
        this.inAppNotifications.set(userId, []);
      }
      
      const userNotifications = this.inAppNotifications.get(userId);
      userNotifications.unshift({
        id: `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        ...notification,
        read: false,
        createdAt: new Date().toISOString()
      });
      
      // Keep only last 50 notifications per user
      if (userNotifications.length > 50) {
        userNotifications.splice(50);
      }
      
      console.log(`Stored in-app notification for user ${userId}: ${notification.title}`);
      
    } catch (error) {
      throw new Error(`In-app notification failed: ${error.message}`);
    }
  }

  /**
   * Send email notification
   * @private
   */
  async sendEmailNotification(notification, userId) {
    try {
      // In a real implementation, you would:
      // 1. Get user email from database
      // 2. Use email service (SendGrid, SES, etc.)
      // 3. Send formatted email
      
      console.log(`Email notification (${this.config.emailProvider}):`, {
        to: `user-${userId}@example.com`, // Would be real email
        subject: notification.title,
        message: notification.message,
        jobId: notification.jobId
      });
      
      // Simulate email sending delay
      await new Promise(resolve => setTimeout(resolve, 100));
      
    } catch (error) {
      throw new Error(`Email notification failed: ${error.message}`);
    }
  }

  /**
   * Send webhook notification
   * @private
   */
  async sendWebhookNotification(notification, userId) {
    try {
      const payload = {
        event: notification.type,
        userId,
        jobId: notification.jobId,
        notification,
        timestamp: new Date().toISOString()
      };
      
      // In a real implementation, you would make HTTP request to webhook URL
      console.log(`Webhook notification to ${this.config.webhookUrl}:`, payload);
      
      // Simulate webhook delay
      await new Promise(resolve => setTimeout(resolve, 200));
      
    } catch (error) {
      throw new Error(`Webhook notification failed: ${error.message}`);
    }
  }

  /**
   * Get in-app notifications for user
   * @param {string} userId - User ID
   * @param {Object} options - Query options
   * @returns {Array} User notifications
   */
  getInAppNotifications(userId, options = {}) {
    const userNotifications = this.inAppNotifications.get(userId) || [];
    
    let filtered = userNotifications;
    
    // Filter by read status
    if (options.unreadOnly) {
      filtered = filtered.filter(n => !n.read);
    }
    
    // Filter by type
    if (options.type) {
      filtered = filtered.filter(n => n.type === options.type);
    }
    
    // Limit results
    const limit = options.limit || 20;
    filtered = filtered.slice(0, limit);
    
    return filtered;
  }

  /**
   * Mark notification as read
   * @param {string} userId - User ID
   * @param {string} notificationId - Notification ID
   */
  markNotificationAsRead(userId, notificationId) {
    const userNotifications = this.inAppNotifications.get(userId) || [];
    const notification = userNotifications.find(n => n.id === notificationId);
    
    if (notification) {
      notification.read = true;
      notification.readAt = new Date().toISOString();
    }
  }

  /**
   * Mark all notifications as read for user
   * @param {string} userId - User ID
   */
  markAllNotificationsAsRead(userId) {
    const userNotifications = this.inAppNotifications.get(userId) || [];
    const now = new Date().toISOString();
    
    userNotifications.forEach(notification => {
      if (!notification.read) {
        notification.read = true;
        notification.readAt = now;
      }
    });
  }

  /**
   * Get notification statistics for user
   * @param {string} userId - User ID
   * @returns {Object} Notification stats
   */
  getNotificationStats(userId) {
    const userNotifications = this.inAppNotifications.get(userId) || [];
    
    return {
      total: userNotifications.length,
      unread: userNotifications.filter(n => !n.read).length,
      byType: userNotifications.reduce((acc, n) => {
        acc[n.type] = (acc[n.type] || 0) + 1;
        return acc;
      }, {}),
      latest: userNotifications[0]?.createdAt || null
    };
  }

  /**
   * Interpolate template variables
   * @private
   */
  interpolateTemplate(template, data) {
    return template.replace(/\{(\w+)\}/g, (match, key) => {
      return data[key] !== undefined ? data[key] : match;
    });
  }

  /**
   * Format duration in human-readable format
   * @private
   */
  formatDuration(milliseconds) {
    if (!milliseconds) return 'unknown';
    
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
   * Clean up old notifications
   * @param {number} maxAge - Maximum age in milliseconds
   */
  cleanupOldNotifications(maxAge = 30 * 24 * 60 * 60 * 1000) { // 30 days default
    const cutoffTime = new Date(Date.now() - maxAge).toISOString();
    let totalCleaned = 0;
    
    for (const [userId, notifications] of this.inAppNotifications.entries()) {
      const originalLength = notifications.length;
      
      // Remove old notifications
      const filtered = notifications.filter(n => n.createdAt > cutoffTime);
      
      if (filtered.length !== originalLength) {
        this.inAppNotifications.set(userId, filtered);
        totalCleaned += originalLength - filtered.length;
      }
      
      // Remove empty user entries
      if (filtered.length === 0) {
        this.inAppNotifications.delete(userId);
      }
    }
    
    console.log(`Cleaned up ${totalCleaned} old notifications`);
    return totalCleaned;
  }

  /**
   * Get service health status
   */
  async getHealthStatus() {
    try {
      const totalNotifications = Array.from(this.inAppNotifications.values())
        .reduce((sum, notifications) => sum + notifications.length, 0);
      
      return {
        status: 'healthy',
        totalUsers: this.inAppNotifications.size,
        totalNotifications,
        channels: {
          inApp: this.config.enableInApp,
          email: this.config.enableEmail,
          webhooks: this.config.enableWebhooks
        },
        config: {
          emailProvider: this.config.emailProvider,
          webhookUrl: this.config.webhookUrl ? 'configured' : 'not configured',
          retryAttempts: this.config.retryAttempts
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
