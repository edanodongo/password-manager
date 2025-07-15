# vault/urls.py
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.urls import reverse_lazy

from .api import StoreCredentialAPI

urlpatterns = [
    # User registration and authentication URLs
    path('register', views.register_view, name='register'),
    
    
    # Login and logout URLs
    path('', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    
    # AJAX URL for validating form fields
    path('validate/', views.validate_field, name='validate_field'),  # New AJAX URL
    
    
    # Dashboard and credential management URLs
    path('dashboard/', views.dashboard, name='dashboard'),
    path('add/', views.add_credential, name='add_credential'),
    path('edit/<int:pk>/', views.edit_credential, name='edit_credential'),
    path('delete/<int:pk>/', views.delete_credential, name='delete_credential'),
    
    
    # logout due to inactivity
    # This URL is used to log out users after a period of inactivity.
    path('logout-inactive/', views.logout_due_to_inactivity, name='logout_inactive'),


    # toggle 2FA status
    # This URL is used to toggle the 2FA status of the user.
    path('account/toggle-2fa/', views.toggle_2fa, name='toggle_2fa'),
    
    
    # 2FA setup and disable URLs
    # These URLs are used for setting up and disabling 2FA for the user.
    path('2fa/setup/', views.setup_2fa, name='setup_2fa'),
    path('2fa/disable/', views.disable_2fa, name='disable_2fa'),


    # 2FA verification URL
    # This URL is used to verify the 2FA code entered by the user.
    path('ajax/check-2fa/', views.check_2fa_status, name='check_2fa_status'),


    # Profile view
    path('profile/', views.profile_view, name='profile'),
    
    

    # api endpoint for storing credentials
    # This endpoint allows authenticated users to store credentials via an API request.
    path('api/save-credential/', views.save_credential_api, name='save_credential_api'),
    
    
    

    # backup code generation and email sending
    path('2fa/send-backup/', views.send_backup_code_email, name='send_backup_code_email'),
    path('2fa/send-backup-code/', views.send_backup_code_email, name='send_backup_code_email'),
 
 
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


    # API endpoint for storing credentials
    # This endpoint allows authenticated users to store credentials via an API request.
    path('api/store/', StoreCredentialAPI.as_view(), name='api_store_credential'),
]
# Note: The views are defined in vault/views.py and handle the logic for each URL.
