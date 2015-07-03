from webapp2_extras.routes import RedirectRoute
import users
import admin
import logsemails
import logsvisits
import crontasks


_routes = [
    RedirectRoute('/admin/', users.AdminStatsHandler, name='admin-stats', strict_slash=True),
    RedirectRoute('/admin/geo/', users.AdminUserGeoChartHandler, name='admin-users-geochart', strict_slash=True),
    RedirectRoute('/admin/users/', users.AdminUserListHandler, name='admin-users-list', strict_slash=True),
    RedirectRoute('/admin/users/export/', users.AdminExportUsers, name='admin-export-users', strict_slash=True),
    RedirectRoute('/admin/homes/', users.AdminHomeListHandler, name='admin-homes-list', strict_slash=True),
    RedirectRoute('/admin/homes/export/', users.AdminExportHomes, name='admin-export-homes', strict_slash=True),
    RedirectRoute('/admin/stores/', users.AdminStoreListHandler, name='admin-stores-list', strict_slash=True),
    RedirectRoute('/admin/stores/export/', users.AdminExportStores, name='admin-export-stores', strict_slash=True),
    
    RedirectRoute('/admin/qubits/', users.AdminQubitListHandler, name='admin-qubits-list', strict_slash=True),
    RedirectRoute('/admin/users/<user_id>/', users.AdminUserEditHandler, name='admin-user-edit', strict_slash=True, handler_method='edit'),
    RedirectRoute('/admin/intakes/', users.AdminIntakesHandler, name='admin-manual-intakes', strict_slash=True),
    RedirectRoute('/admin/intakes/sorter/', users.AdminHomeIntakesSorter, name='admin-intakes-sorter', strict_slash=True),
    RedirectRoute('/admin/estimator/', users.AdminEstimatorHandler, name='admin-estimator', strict_slash=True),
    RedirectRoute('/admin/box/', users.AdminBoxHandler, name='admin-box', strict_slash=True),

    RedirectRoute('/admin/logs/emails/', logsemails.AdminLogsEmailsHandler, name='admin-logs-emails', strict_slash=True),
    RedirectRoute('/admin/logs/emails/<email_id>/', logsemails.AdminLogsEmailViewHandler, name='admin-logs-email-view', strict_slash=True),
    RedirectRoute('/admin/logs/visits/', logsvisits.AdminLogsVisitsHandler, name='admin-logs-visits', strict_slash=True),

    RedirectRoute('/admin/logout/', admin.AdminLogoutHandler, name='admin-logout', strict_slash=True),
    RedirectRoute('/crontasks/cleanuptokens/', crontasks.AdminCleanupTokensHandler, name='admin-crontasks-cleanuptokens', strict_slash=True),

]

def get_routes():
    return _routes

def add_routes(app):
    for r in _routes:
        app.router.add(r)
