# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/dotnet/sdk:9.0.321 AS build
WORKDIR /src
COPY Bench.csproj .
RUN dotnet restore
COPY Program.cs ViewMac.cs ./
RUN dotnet publish -c Release -o /out --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:9.0.23
WORKDIR /app
COPY --from=build /out .
ENV ASPNETCORE_HTTP_PORTS=8080 FRAMEWORK_TAG=aspnet OVERRIDE=off VERIFY_MODE=off \
    Logging__LogLevel__Default=Warning DOTNET_gcServer=0
EXPOSE 8080
ENTRYPOINT ["dotnet", "Bench.dll"]

# W15 ext-routes: ROUTES=v2 enables the richer v1 route space (build :v2 with --build-arg ROUTES=v2).
ARG ROUTES=off
ENV ROUTES=${ROUTES}
