import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('usuarios', '0002_usuario_codigo_recuperacion'),
    ]

    operations = [
        migrations.AlterField(
            model_name='rol',
            name='cod_rol',
            field=models.CharField(max_length=10, primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='usuario',
            name='contrasena',
            field=models.CharField(max_length=100),
        ),
        migrations.CreateModel(
            name='Bitacora',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('accion', models.CharField(max_length=100)),
                ('detalles', models.TextField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('usuario', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='bitacoras', to='usuarios.usuario')),
            ],
            options={
                'verbose_name': 'Bitacora',
                'verbose_name_plural': 'Bitacoras',
                'ordering': ['-timestamp'],
            },
        ),
    ]
