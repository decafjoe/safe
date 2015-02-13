from clik import app


__version__ = '0.2'


@app
def safe():
    yield
    print 'Hello, world!'


if __name__ == '__main__':  # pragma: no cover
    safe.main()
