# Copyright Istio Authors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

# Runtime remains the official Bookinfo reviews-v2 image used by the Docker
# Compose Bookinfo service. We only replace the WAR, which is built from
# official source with X-Mark propagation added.
FROM docker.io/istio/examples-bookinfo-reviews-v2:1.20.3

ENV SERVERDIRNAME reviews

COPY reviews-application-1.0-rid.war /opt/ol/wlp/usr/servers/defaultServer/apps/reviews-application-1.0.war

ARG service_version
ARG enable_ratings
ARG star_color
ENV SERVICE_VERSION ${service_version:-v2}
ENV ENABLE_RATINGS ${enable_ratings:-true}
ENV STAR_COLOR ${star_color:-black}

CMD ["/opt/ol/wlp/bin/server", "run", "defaultServer"]
