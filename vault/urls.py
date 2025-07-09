# vault/urls.py
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.urls import reverse_lazy

urlpatterns = [
    path('', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('validate/', views.validate_field, name='validate_field'),  # New AJAX URL
    

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
