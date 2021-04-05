from django.shortcuts import render
# Create your views here.
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.contrib.auth import login,logout
from django.contrib.auth.hashers import check_password
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.csrf import csrf_exempt
class login_api(APIView):
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [AllowAny]
    @csrf_exempt
    def post(self, request, format=None):
        data = request.data
        print(data)
        # return Response("done")
        user_name = data["username"]
        password = data["password"]
        print(user_name,password)
        user = authenticate(username=user_name, password=password)
        print(user)
        if user and user.is_active:
            login(self.request, user)
            return Response("welcome")
        else:
            try:
                context = ""
                user = User.objects.get(username__iexact=user_name)
                if not check_password(password, user.password):
                    context = "NO PASSCODE"
            except User.DoesNotExist:
                context = "NO USER"
            return Response(context)


class CSRFExemptAuthentication(SessionAuthentication):
    def enforce_csrf(self, request):
        return


class logout_api(APIView):
    authentication_classes = [CSRFExemptAuthentication]
    permission_classes = [IsAuthenticated]
    
    @csrf_exempt
    def post(self, request, format=None):
        user = request.user
        print(user)
        if user and user.is_active:
            logout(request)
            return Response("logout")
        else:
            return Response("some issue in logout")