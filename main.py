from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import engine
import models
from fastapi_jwt_auth import AuthJWT
import inspect, re
from fastapi.openapi.utils import get_openapi
from fastapi.routing import APIRoute
from schemas import Settings
from resources.role import role_router
from resources.role_user import role_user_router



app=FastAPI()

app.include_router(role_router)
app.include_router(role_user_router)



def custom_openapi():
    if app.openapi_schema: 
        return app.openapi_schema 

    openapi_schema = get_openapi(
        title = "Role Management API",
        version = "1.0",
        description = "An API for a Role Service",
        routes = app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "Bearer Auth": {
            "type": "apiKey",
            "in": "header",
            "name": "Authorization",
            "description": "Enter: **'Bearer &lt;JWT&gt;'**, where JWT is the access token"
        }
    }

    # Get all routes where jwt_optional() or jwt_required
    api_router = [route for route in app.routes if isinstance(route, APIRoute)]

    for route in api_router:
        path = getattr(route, "path")
        endpoint = getattr(route,"endpoint")
        methods = [method.lower() for method in getattr(route, "methods")]

        for method in methods:
            # access_token
            if (
                re.search("jwt_required", inspect.getsource(endpoint)) or
                re.search("fresh_jwt_required", inspect.getsource(endpoint)) or
                re.search("jwt_optional", inspect.getsource(endpoint))
            ):
                openapi_schema["paths"][path][method]["security"] = [
                    {
                        "Bearer Auth": []
                    }
                ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

    
@AuthJWT.load_config
def get_config():
    return Settings()

app.openapi = custom_openapi



models.Base.metadata.create_all(engine)





origins=[
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)