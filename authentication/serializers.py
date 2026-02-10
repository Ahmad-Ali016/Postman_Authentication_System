from django.contrib.auth.models import User
from rest_framework import serializers
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes


class SignupSerializer(serializers.ModelSerializer):
    # These two are for the 'Password Match' logic
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    # These are extra fields you asked for
    age = serializers.IntegerField(write_only=True)
    phone = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'age', 'phone', 'password', 'confirm_password']

    # This function checks if the user typed the same password twice
    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match!")
        return data

    # This saves the user to the database
    def create(self, validated_data):
        # Extract the password from the data
        password = validated_data.pop('password')
        validated_data.pop('confirm_password')

        # 1. Create the user but set is_active to False
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
        )
        # Scramble the password so Django can read it later
        user.set_password(password)
        user.is_active = False  # User cannot log_in yet!
        user.save()

        # 2. Generate a unique token and a Base64 version of the User ID
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # 3. Create the "Activation Link"
        activation_link = f"http://127.0.0.1:8000/api/activate/{uid}/{token}/"

        # 4. "Print" the email to the terminal (Mocking the email server)
        print("\n" + "=" * 50)
        print(f"SUBJECT: Activate Your Account")
        print(f"TO: {user.email}")
        print(f"BODY: Please click the link below to verify your account:")
        print(f"\n{activation_link}\n")
        print("=" * 50 + "\n")

        return user