from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PromocionViewSet

router = DefaultRouter()
router.register(r'promociones', PromocionViewSet, basename='promociones')

urlpatterns = [
    path('', include(router.urls)),
]
