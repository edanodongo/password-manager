# vault/urls.py
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.urls import reverse_lazy

urlpatterns = [
    path('register', views.register_view, name='register'),
    path('', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('validate/', views.validate_field, name='validate_field'),  # New AJAX URL
    
    path('dashboard/', views.dashboard, name='dashboard'),
    path('add/', views.add_credential, name='add_credential'),
    path('edit/<int:pk>/', views.edit_credential, name='edit_credential'),
    path('delete/<int:pk>/', views.delete_credential, name='delete_credential'),
    
    path('logout-inactive/', views.logout_due_to_inactivity, name='logout_inactive'),

    path('account/toggle-2fa/', views.toggle_2fa, name='toggle_2fa'),
    
    path('2fa/setup/', views.setup_2fa, name='setup_2fa'),
    path('2fa/disable/', views.disable_2fa, name='disable_2fa'),

    
    # view to load the 2FA status via AJAX in profile page without page reload
    # path('ajax/check-2fa/', views.check_2fa_status, name='check_2fa_status'),


    path('ajax/check-2fa/', views.check_2fa_status, name='check_2fa_status'),

    # Profile view
    path('profile/', views.profile_view, name='profile'),

    # Password reset request form
    path('password_reset/', auth_views.PasswordResetView.as_view(
        template_name='pass_reset/password_reset.html',
        # email_template_name='pass_reset/password_reset_email.html',
        # subject_template_name='pass_reset/password_reset_subject.txt',
        success_url=reverse_lazy('password_reset_done')
    ), name='password_reset'),

    # Password reset done (email sent confirmation)
    path('password_reset_done/', auth_views.PasswordResetDoneView.as_view(
        template_name='pass_reset/password_reset_done.html'
    ), name='password_reset_done'),

    # Password reset confirm (link from email)
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='pass_reset/password_reset_confirm.html',
        success_url=reverse_lazy('password_reset_complete')
    ), name='password_reset_confirm'),

    # Password reset complete (password successfully changed)
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(
        template_name='pass_reset/password_reset_complete.html'
    ), name='password_reset_complete'),

]
# Note: Ensure that the views are defined in vault/views.py as per the previous code snippets.
