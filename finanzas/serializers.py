from rest_framework import serializers

from .models import Opinion


class OpinionSerializer(serializers.ModelSerializer):
    cliente_nombre = serializers.ReadOnlyField(source='usuario.nombre')
    cliente_correo = serializers.ReadOnlyField(source='usuario.correo')
    pedido_codigo = serializers.SerializerMethodField()

    class Meta:
        model = Opinion
        fields = [
            'id',
            'usuario',
            'cliente_nombre',
            'cliente_correo',
            'pedido',
            'pedido_codigo',
            'calificacion',
            'comentario',
            'fecha',
            'visible',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'usuario',
            'cliente_nombre',
            'cliente_correo',
            'fecha',
            'visible',
            'created_at',
            'updated_at',
        ]

    def get_pedido_codigo(self, obj):
        return f'PED-{obj.pedido_id:03d}' if obj.pedido_id else None

    def validate_calificacion(self, value):
        if value < 1 or value > 5:
            raise serializers.ValidationError('La calificación debe estar entre 1 y 5 estrellas.')
        return value

    def validate_comentario(self, value):
        texto = (value or '').strip()
        if len(texto) > 500:
            raise serializers.ValidationError('El comentario no puede superar los 500 caracteres.')
        return texto
