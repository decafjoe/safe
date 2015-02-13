from clik import app


__version__ = '0.2'


@app
def safe():
    yield
    print 'Hello, world!'


main = safe.main


if __name__ == '__main__':
    main()
