from rest_framework.permissions import BasePermission


class IsCocinero(BasePermission):
    def has_permission(self, request, view):
        usuario = getattr(request, 'user', None)
        if not usuario:
            return False
        cod_rol = getattr(getattr(usuario, 'cod_rol', None), 'cod_rol', None)
        return bool(cod_rol and cod_rol.lower() == 'cocinero')
