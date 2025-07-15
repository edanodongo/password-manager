# vault/forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import CustomUser, Credential



# Custom user registration form

class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password1', 'password2']



# Credential form for adding/editing credentials

class CredentialForm(forms.ModelForm):
    password_raw = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Enter password'}),
        label="Password"
    )

    class Meta:
        model = Credential
        fields = ['platform_type', 'name', 'username', 'url_or_developer', 'notes']

    def save(self, commit=True, user=None):
        instance = super().save(commit=False)
        if user:
            instance.user = user
        instance.set_password(self.cleaned_data['password_raw'])
        if commit:
            instance.save()
        return instance



# Profile update form for changing email and password

class ProfileUpdateForm(forms.ModelForm):
    email = forms.EmailField(required=True, label='New Email')
    password = forms.CharField(required=False, label='New Password', widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ['email', 'password']

    def save(self, commit=True):
        user = super().save(commit=False)
        password = self.cleaned_data.get('password')
        if password:
            user.set_password(password)
        if commit:
            user.save()
        return user