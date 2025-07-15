from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.contrib.auth import authenticate
from .models import Credential
import json

def authenticate_with_api_key(api_key):
    # Replace this with your actual API key authentication logic
    from django.contrib.auth.models import User
    try:
        # Example: Assume api_key is the user's username for demonstration
        return User.objects.get(username=api_key)
    except User.DoesNotExist:
        return None

@method_decorator(csrf_exempt, name='dispatch')
class StoreCredentialAPI(View):
    def post(self, request):
        try:
            data = json.loads(request.body)

            username = data.get('username')
            password = data.get('password')
            site = data.get('site')
            api_key = data.get('api_key')

            # 1. Authenticate using API key
            user = authenticate_with_api_key(api_key)
            if not user:
                return JsonResponse({'success': False, 'message': 'Unauthorized'}, status=401)

            # 2. Validate input
            if not all([site, username, password]):
                return JsonResponse({'success': False, 'message': 'Missing fields'}, status=400)

            # 3. Save the credential
            Credential.objects.create(user=user, site=site, username=username, password=password)

            return JsonResponse({'success': True, 'message': 'Credential stored'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': str(e)}, status=500)
