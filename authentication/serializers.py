from django.contrib.auth.models import User
from rest_framework import serializers
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes


class SignupSerializer(serializers.ModelSerializer):
    # These two are for the 'Password Match' logic
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    # These are extra fields
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
        # Extract and SAVE the values into variables
        password = validated_data.pop('password')
        validated_data.pop('confirm_password', None)

        # We save 'age' and 'phone' to variables so we can use them in the print statement
        age = validated_data.pop('age', None)
        phone = validated_data.pop('phone', None)

        # CREATE USER
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=password,
            is_active=False
        )

        # Generate security tokens
        uid = urlsafe_base64_encode(force_bytes(str(user.pk)))
        token = default_token_generator.make_token(user)

        # Activation Link
        activation_link = f"http://127.0.0.1:8000/api/activate/{uid}/{token}/"

        # 5. Terminal Output (Now 'age' and 'phone' are defined!)
        print("\n" + "=" * 50)
        print(f"SUBJECT: Activate Your Account")
        print(f"TO: {user.email}")
        print(f"AGE: {age} | PHONE: {phone}")  # Proof we captured custom fields
        print(f"BODY: Please click the link below to verify your account:")
        print(f"\n{activation_link}\n")
        print("=" * 50 + "\n")

        return user