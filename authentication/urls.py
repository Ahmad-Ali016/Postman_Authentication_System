from django.urls import path

from authentication.views import SignupView, LoginView

urlpatterns = [
    path('register/', SignupView.as_view()),
    path('login/', LoginView.as_view()),
]