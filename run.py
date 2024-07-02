from  app import create_app




def run_flask_app():
    app = create_app()
    app.run(debug = True)
    

if __name__ == '__main__':
    run_flask_app( )