from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.db import IntegrityError
from django.utils import timezone
from .forms import TaskForm
from .models import Task


def home(request):
    return render(request, 'home.html')


def signup(request):
    context = {
        'form': UserCreationForm(),
        'error': ''
    }
    if request.method == 'GET':
        return render(request, 'signup.html', context)
    else:
        if request.POST['password1'] == request.POST['password2']:
            try:
                user = User.objects.create_user(
                    username=request.POST['username'], password=request.POST['password1'])
                user.save()
                login(request, user)
                # return HttpResponse('User created successfully')
                return redirect('tasks')
            except Exception as err:
                context['error'] = 'Username already exists'
                return render(request, 'signup.html', context)

        context['error'] = 'Password do not match'
        return render(request, 'signup.html', context)

@login_required
def signout(request):
    logout(request)
    return redirect('home')


def signin(request):
    context = {
        'form': AuthenticationForm(),
        'error': ''
    }
    if request.method == 'GET':
        return render(request, 'signin.html', context)
    else:
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)

        if user is None:
            context['error'] = 'Username or password is incorrect.'
            return render(request, 'signin.html', context)

        login(request, user)
        return redirect('tasks')

@login_required
def tasks(request):
    tasks = Task.objects.filter(user=request.user, datecompleted__isnull=True)
    context = {
        'tasks': tasks
    }
    return render(request, 'tasks.html', context)


@login_required
def tasks_completed(request):
    tasks = Task.objects.filter(user=request.user, datecompleted__isnull=False).order_by('-datecompleted')
    context = {
        'tasks': tasks
    }
    return render(request, 'tasks.html', context)
    

@login_required
def task_complete(request, id):
    task = get_object_or_404(Task, pk=id, user=request.user)
    task.datecompleted = timezone.now()
    task.save()
    return redirect('tasks')


@login_required
def task_delete(request, id):
    task = get_object_or_404(Task, pk=id, user=request.user)
    task.delete()
    return redirect('tasks')


@login_required
def task_detail(request, id):
    task = get_object_or_404(Task, pk=id, user=request.user)
    if request.method == 'GET':
        form = TaskForm(instance=task)
        context = {
            'form': form,
            'task': task
        }
        return render(request, 'task_detail.html', context)

    # actualizar task
    try:
        form = TaskForm(request.POST, instance=task)
        form.save()
        return redirect('tasks')
    except ValueError as err:
        context = {
            'form': TaskForm(instance=task),
            'error': 'Error updating task'
        }
        return render(request, 'task_detail.html', context)


@login_required
def task_create(request):
    context = {
        'form': TaskForm,
        'error': ''
    }
    if request.method == 'GET':
        return render(request, 'task_create.html', context)

    try:
        form = TaskForm(request.POST)
        new_task = form.save(commit=False)
        new_task.user = request.user
        new_task.save()
        return redirect('tasks')
    except ValueError as err:
        context['error'] = 'Please provide valida data'
        return render(request, 'task_create.html', context)