from invoke import task
from invoke import run


@task
def virtualenv(ctx):
    run("virtualenv --prompt ')> Pygo <( ' env --python python3.7")
    run("env/bin/pip install -r requirements.txt")
    print("\nVirtualENV Setup Complete.  Now run: source env/bin/activate\n")


@task
def clean(ctx):
    run("rm -rvf __pycache__")
