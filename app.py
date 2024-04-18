from routers.authentication import router as authentication_router
from routers.crud_operations import router as crud_router
from helpers.response_format import http_response
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI


__version__ = "1.0.0"

app = FastAPI(title="Technical Assessment",
              version=__version__)

# Configure CORS
app.add_middleware(
                    CORSMiddleware,
                    allow_origins=["*"],
                    allow_methods=["GET", "POST", "PUT", "DELETE"],
                    allow_headers=["*"],
                    allow_credentials=True,
                  )

app.include_router(authentication_router,  prefix="/auth", tags=["Authentication"])
app.include_router(crud_router,  prefix="/user", tags=["CRUD Operations"])


@app.get("/healthcheck", description="Checks if the APIs are reachable and provides the version.")
def test():
    response = {
                "health": "Healthy :)",
                "version": __version__
                }
    return http_response(data=response)
