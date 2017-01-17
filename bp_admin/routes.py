from webapp2_extras.routes import RedirectRoute
import handlers_users
import handlers_essentials
import handlers_blog
import handlers_emails
import handlers_crontasks


_routes = [
    RedirectRoute('/admin/logout/', handlers_essentials.AdminLogoutHandler, name='admin-logout', strict_slash=True),
    RedirectRoute('/admin/brand/', handlers_essentials.AdminBrandHandler, name='admin-brand', strict_slash=True),
    RedirectRoute('/admin/contents/', handlers_essentials.AdminContentsHandler, name='admin-contents', strict_slash=True),
    RedirectRoute('/admin/delete/<content_id>/', handlers_essentials.AdminContentDeleteHandler, name='admin-content-delete', strict_slash=True),
    RedirectRoute('/admin/show/<content_id>/', handlers_essentials.AdminContentShowHandler, name='admin-content-show', strict_slash=True),
    RedirectRoute('/admin/hide/<content_id>/', handlers_essentials.AdminContentHideHandler, name='admin-content-hide', strict_slash=True),
    RedirectRoute('/admin/specials/', handlers_essentials.AdminSpecialsHandler, name='admin-specials', strict_slash=True),
    RedirectRoute('/admin/specials/<operator_id>/', handlers_essentials.AdminSpecialsEditHandler, name='admin-specials-edit', strict_slash=True, handler_method='edit'),
    RedirectRoute('/admin/', handlers_users.AdminStatsHandler, name='admin', strict_slash=True),
    RedirectRoute('/admin/blog/', handlers_blog.AdminBlogHandler, name='admin-blog', strict_slash=True),
    RedirectRoute('/admin/blog/<post_id>/', handlers_blog.AdminBlogEditHandler, name='admin-blog-edit', strict_slash=True),
    RedirectRoute('/admin/blog/upload/<post_id>/', handlers_blog.AdminBlogUploadHandler, name='admin-blog-upload', strict_slash=True),
    RedirectRoute('/admin/blog/tools/css/', handlers_blog.AdminCSSHandler, name='admin-tools-css', strict_slash=True),
    RedirectRoute('/admin/blog/tools/icons/', handlers_blog.AdminIconsHandler, name='admin-tools-icons', strict_slash=True),
    RedirectRoute('/admin/blog/tools/media/', handlers_blog.AdminMediaHandler, name='admin-tools-media', strict_slash=True),
    RedirectRoute('/admin/users/', handlers_users.AdminUserListHandler, name='admin-users-list', strict_slash=True),
    RedirectRoute('/admin/users/export/', handlers_users.AdminExportUsers, name='admin-export-users', strict_slash=True),
    RedirectRoute('/admin/users/<user_id>/', handlers_users.AdminUserEditHandler, name='admin-user-edit', strict_slash=True, handler_method='edit'),
    RedirectRoute('/admin/logs/emails/', handlers_emails.AdminLogsEmailsHandler, name='admin-logs-emails', strict_slash=True),
    RedirectRoute('/admin/logs/emails/<email_id>/', handlers_emails.AdminLogsEmailViewHandler, name='admin-logs-email-view', strict_slash=True),
    RedirectRoute('/admin/logs/visits/', handlers_users.AdminLogsVisitsHandler, name='admin-logs-visits', strict_slash=True),
    RedirectRoute('/admin/send/email/', handlers_emails.AdminSendEmailListHandler, name='admin-send-email', strict_slash=True),
    RedirectRoute('/admin/crontasks/cleanuptokens/', handlers_crontasks.AdminCleanupTokensHandler, name='admin-crontasks-cleanuptokens', strict_slash=True),
    RedirectRoute('/_ah/bounce', handlers_emails.LogBounceHandler, name='bouncer', strict_slash=True),
]

def get_routes():
    return _routes

def add_routes(app):
    for r in _routes:
        app.router.add(r)
