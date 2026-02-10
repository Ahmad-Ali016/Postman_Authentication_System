from django.urls import path

from authentication.views import SignupView, LoginView, ActivateAccountView, RequestPasswordResetView, \
    ResetPasswordConfirmView

urlpatterns = [
    path('register/', SignupView.as_view()),
    path('login/', LoginView.as_view()),
    path('activate/<str:uidb64>/<str:token>/', ActivateAccountView.as_view()),
    path('request-reset/', RequestPasswordResetView.as_view()),
    path('reset-password/<str:uidb64>/<str:token>/', ResetPasswordConfirmView.as_view()),
]