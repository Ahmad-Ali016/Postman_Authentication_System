from django.urls import path

from authentication.views import SignupView, LoginView, ActivateAccountView

urlpatterns = [
    path('register/', SignupView.as_view()),
    path('login/', LoginView.as_view()),
    path('activate/<str:uidb64>/<str:token>/', ActivateAccountView.as_view()),
]