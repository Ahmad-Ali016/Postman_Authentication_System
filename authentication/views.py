from jwt.utils import force_bytes
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import SignupSerializer

from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode  # To decode the scrambled ID from the link
from django.utils.encoding import force_str  # To convert bytes back into a readable string
from django.contrib.auth.models import User  # To look up the user in the database
from django.contrib.auth.tokens import default_token_generator  # To verify the security token

from rest_framework.permissions import IsAuthenticated



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


class RequestPasswordResetView(APIView):
    def post(self, request):
        # Grab the email from the request body
        email = request.data.get('email')

        # Try to find the user associated with that email
        user = User.objects.filter(email=email).first()

        if user is not None:
            # Scramble the User ID into a string for the URL
            uid = urlsafe_base64_encode(force_bytes(str(user.pk)))

            # Generate the unique one-time security token
            token = default_token_generator.make_token(user)

            # Create the reset link
            reset_link = f"http://127.0.0.1:8000/api/reset-password/{uid}/{token}/"

            # Print the "Email" to the terminal
            print("\n" + "=" * 50)
            print(f"PASSWORD RESET LINK FOR: {user.username}")
            print(reset_link)
            print("=" * 50 + "\n")

            return Response({"message": "Password reset link sent to your terminal."}, status=status.HTTP_200_OK)

            # Safety: We don't tell the sender if the email exists or not (security best practice)
        return Response({"error": "If an account exists with this email, a link has been sent."},
                        status=status.HTTP_200_OK)


class ResetPasswordConfirmView(APIView):
    def post(self, request, uidb64, token):
        # Grab the new password from the user's input
        new_password = request.data.get('new_password')

        try:
            # Decode the User ID from the link
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        # Check if the token is valid for this specific user
        if user is not None and default_token_generator.check_token(user, token):
            # Use set_password to hash the new password correctly
            user.set_password(new_password)
            user.save()

            return Response({"message": "Password reset successful! You can now login."}, status=status.HTTP_200_OK)

        # Fail if the token is old or tampered with
        return Response({"error": "Invalid or expired reset link."}, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(APIView):
    # Only logged-in users with a valid token can access this
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Grab the old and new passwords from the request body
        old_password = request.data.get("old_password")
        new_password = request.data.get("new_password")
        user = request.user # Django already knows who this is from the token

        # Verify that the 'old_password' matches what is in the database
        if not user.check_password(old_password):
            return Response({"error": "Old password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

        # Securely hash and save the new password
        user.set_password(new_password)
        user.save()

        # Return success message
        return Response({"message": "Password updated successfully!"}, status=status.HTTP_200_OK)