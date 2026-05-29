from rest_framework import serializers
from django.db.models import Sum
from .models import SalaTematica, Mesa, Reserva, SalaImagen
from usuarios.models import Cliente

class SalaImagenSerializer(serializers.ModelSerializer):
    class Meta:
        model = SalaImagen
        fields = ['id', 'imagen', 'fecha_subida']

class SalaTematicaSerializer(serializers.ModelSerializer):
    galeria = SalaImagenSerializer(many=True, read_only=True)

    class Meta:
        model = SalaTematica
        fields = '__all__'

class MesaSerializer(serializers.ModelSerializer):
    sala_nombre = serializers.ReadOnlyField(source='sala.nombre')

    class Meta:
        model = Mesa
        fields = '__all__'

    def validate(self, data):
        capacidad = data.get('capacidad')
        sala = data.get('sala')
        
        if capacidad is not None:
            if capacidad <= 0:
                raise serializers.ValidationError({"capacidad": "La capacidad debe ser mayor que 0."})
            if capacidad % 2 != 0:
                raise serializers.ValidationError({"capacidad": "La capacidad de la mesa debe ser un número par."})
            if sala and sala.capacidad_total > 0:
                if capacidad > sala.capacidad_total:
                    raise serializers.ValidationError({"capacidad": "La capacidad de la mesa no puede superar la capacidad máxima permitida."})
                
                existing_mesas = sala.mesas.filter(activa=True)
                if self.instance:
                    existing_mesas = existing_mesas.exclude(pk=self.instance.pk)
                
                capacidad_usada = existing_mesas.aggregate(Sum('capacidad'))['capacidad__sum'] or 0
                if capacidad + capacidad_usada > sala.capacidad_total:
                    raise serializers.ValidationError({"capacidad": "La capacidad de esta mesa supera la capacidad disponible de la sala."})
        
        return data

class ReservaSerializer(serializers.ModelSerializer):
    cliente_nombre = serializers.ReadOnlyField(source='cliente.id_usuario.nombre')
    sala_nombre = serializers.ReadOnlyField(source='sala.nombre')
    mesa_nombre = serializers.ReadOnlyField(source='mesa.nombre')

    class Meta:
        model = Reserva
        fields = '__all__'
