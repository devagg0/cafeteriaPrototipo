from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import PromocionViewSet


router = DefaultRouter()
router.register('promociones', PromocionViewSet, basename='promociones')

urlpatterns = [
    path('', include(router.urls)),
]
