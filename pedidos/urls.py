from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PedidoViewSet, PreordenViewSet

router = DefaultRouter()
router.register(r'pedidos', PedidoViewSet, basename='pedidos')
router.register(r'preordenes', PreordenViewSet, basename='preordenes')

urlpatterns = [
    path('', include(router.urls)),
]
