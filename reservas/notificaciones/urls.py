from django.urls import path
from . import views

urlpatterns = [
    path('', views.HistorialNotificacionesView.as_view()),
    path('mis/', views.MisNotificacionesView.as_view()),
    path('count/', views.ContadorNoLeidasView.as_view()),
    path('<int:pk>/marcar-leido/', views.MarcarLeidoView.as_view()),
    path('enviar/', views.EnviarNotificacionManualView.as_view()),
]