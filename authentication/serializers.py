from django.contrib.auth.models import User
from rest_framework import serializers


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
        # We remove confirm_password, age, and phone because
        # the default Django User model doesn't have columns for them yet.
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user
