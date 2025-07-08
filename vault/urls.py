# vault/urls.py
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('validate/', views.validate_field, name='validate_field'),  # New AJAX URL
    
    # This code adds password reset functionality to the existing URL patterns.
    path('password_reset/', auth_views.PasswordResetView.as_view(
        template_name='vault/password_reset.html'
    ), name='password_reset'),

    path('password_reset_done/', auth_views.PasswordResetDoneView.as_view(
        template_name='vault/password_reset_done.html'
    ), name='password_reset_done'),

    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(
        template_name='vault/password_reset_confirm.html'
    ), name='password_reset_confirm'),

    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(
        template_name='vault/password_reset_complete.html'
    ), name='password_reset_complete'),
]
# Note: Ensure that the views are defined in vault/views.py as per the previous code snippets.

