from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import SignupSerializer

from django.utils.http import urlsafe_base64_decode  # To decode the scrambled ID from the link
from django.utils.encoding import force_str  # To convert bytes back into a readable string
from django.contrib.auth.models import User  # To look up the user in the database
from django.contrib.auth.tokens import default_token_generator  # To verify the security token


# Create your views here.

# THE SIGNUP VIEW
class SignupView(APIView):
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"msg": "User Created!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# THE LOGIN VIEW
class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        # 1. First, just try to find the user by username
        try:
            user_obj = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # 2. Check the password manually
        if not user_obj.check_password(password):
            return Response({"error": "Wrong password"}, status=status.HTTP_401_UNAUTHORIZED)

        # 3. Check if they are active
        if not user_obj.is_active:
            print(f"DEBUG: User {user_obj.username} is FOUND but is_active is FALSE")
            return Response({
                "error": "Account not active. Please click the link in your terminal."
            }, status=status.HTTP_401_UNAUTHORIZED)

        # 4. If everything is perfect, give tokens
        refresh = RefreshToken.for_user(user_obj)
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'message': 'Login successful!'
        })

        # 4. Fail! If the user wasn't found at all (wrong password/username)
        # return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)


class ActivateAccountView(APIView):
    """
    This view handles the 'click' on the activation link.
    The user sends a GET request to this URL.
    """

    def get(self, request, uidb64, token):
        try:
            # Convert the scrambled Base64 string back into a numeric User ID
            uid = force_str(urlsafe_base64_decode(uidb64))

            # Search the database for the user that matches this ID
            user = User.objects.get(pk=uid)

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            # If the ID is invalid or the user doesn't exist, set to None
            user = None

        # Check if the user exists and if the security token matches that specific user
        if user is not None and default_token_generator.check_token(user, token):
            # Change the user's status from 'inactive' to 'active' so they can log_in
            user.is_active = True

            # Save the updated 'is_active' status into the database
            user.save()

            return Response({"message": "Account activated!"}, status=status.HTTP_200_OK)

        else:
            # If the token is fake, already used, or expired, return an error
            return Response({"error": "Invalid link"}, status=status.HTTP_400_BAD_REQUEST)
