# vault/forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']




from django import forms
from .models import Credential

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
