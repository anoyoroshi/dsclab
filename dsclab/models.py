from django.db import models

class User(models.Model):
    name = models.CharField(max_length=50)
    password = models.CharField(max_length=30)
    secret = models.CharField(max_length=4)
    phone = models.CharField(max_length=20, blank=True, null=True)
    mail = models.EmailField(max_length=100, blank=True, null=True)

    def __str__(self):
        return name

    class Meta:
        ordering = ["name",]

