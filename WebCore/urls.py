"""
URL configuration for WebCore project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from AppCore import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
    path('tasks/', views.tasks, name='tasks'),
    path('tasks/completed/', views.tasks_completed, name='tasks_completed'),
    path('tasks/create/', views.task_create, name='task_create'),
    path('tasks/<int:id>/', views.task_detail, name='task_detail'),
    path('tasks/<int:id>/complete', views.task_complete, name='task_complete'),
    path('tasks/<int:id>/delete', views.task_delete, name='task_delete'),
    path('signup/', views.signup, name='signup'),
    path('signout/', views.signout, name='signout'),
    path('signin/', views.signin, name='signin'),
]