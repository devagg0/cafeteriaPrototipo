from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('finanzas', '0003_pago_cierre_caja'),
        ('pedidos', '0006_detallepreorden_observaciones'),
        ('usuarios', '0009_usuario_foto_perfil'),
    ]

    operations = [
        migrations.CreateModel(
            name='Opinion',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('calificacion', models.PositiveSmallIntegerField()),
                ('comentario', models.CharField(blank=True, max_length=500)),
                ('fecha', models.DateField(default=django.utils.timezone.localdate)),
                ('visible', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('pedido', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='opiniones', to='pedidos.pedido')),
                ('usuario', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='opiniones', to='usuarios.usuario')),
            ],
            options={
                'db_table': 'opinion',
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddConstraint(
            model_name='opinion',
            constraint=models.CheckConstraint(condition=models.Q(('calificacion__gte', 1), ('calificacion__lte', 5)), name='opinion_calificacion_1_5'),
        ),
        migrations.AddConstraint(
            model_name='opinion',
            constraint=models.UniqueConstraint(fields=('usuario', 'fecha'), name='opinion_unica_usuario_fecha'),
        ),
    ]
