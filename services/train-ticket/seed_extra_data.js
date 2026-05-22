// Idempotent 20-station seed data for the TrainTicket preserve benchmark.
// Run from any TrainTicket Mongo container on the compose network:
//   docker compose -f docker-compose.yml exec -T ts-station-mongo mongo --quiet < seed_extra_data.js

var trainTypes = ["GaoTieOne", "GaoTieTwo", "ZhiDa", "TeKuai", "KuaiSu"];
var stations = [
  {id: "shanghai", name: "Shang Hai", stayTime: 10},
  {id: "shanghaihongqiao", name: "Shang Hai Hong Qiao", stayTime: 10},
  {id: "suzhou", name: "Su Zhou", stayTime: 3},
  {id: "wuxi", name: "Wu Xi", stayTime: 3},
  {id: "changzhou", name: "Chang Zhou", stayTime: 4},
  {id: "zhenjiang", name: "Zhen Jiang", stayTime: 2},
  {id: "nanjing", name: "Nan Jing", stayTime: 8},
  {id: "xuzhou", name: "Xu Zhou", stayTime: 7},
  {id: "jinan", name: "Ji Nan", stayTime: 5},
  {id: "beijing", name: "Bei Jing", stayTime: 10},
  {id: "tianjin", name: "Tian Jin", stayTime: 6},
  {id: "shijiazhuang", name: "Shi Jia Zhuang", stayTime: 8},
  {id: "taiyuan", name: "Tai Yuan", stayTime: 5},
  {id: "hangzhou", name: "Hang Zhou", stayTime: 9},
  {id: "jiaxingnan", name: "Jia Xing Nan", stayTime: 2},
  {id: "ningbo", name: "Ning Bo", stayTime: 5},
  {id: "hefei", name: "He Fei", stayTime: 5},
  {id: "wuhan", name: "Wu Han", stayTime: 7},
  {id: "changsha", name: "Chang Sha", stayTime: 6},
  {id: "guangzhou", name: "Guang Zhou", stayTime: 8}
];

function serviceDb(serviceName) {
  return new Mongo(serviceName + ":27017").getDB("ts");
}

function stationPair(number) {
  var idx = number - 1345;
  var start = stations[idx % stations.length];
  var terminal = stations[(idx + 2) % stations.length];
  return {start: start, terminal: terminal};
}

function routeIdFor(number) {
  var pair = stationPair(number);
  return "tf-" + pair.start.id + "-" + pair.terminal.id + "-" + number;
}

function activeRouteIds() {
  var ids = [];
  for (var number = 1345; number <= 1444; number += 1) {
    ids.push(routeIdFor(number));
  }
  return ids;
}

function seedStations(stationDb) {
  stations.forEach(function(station) {
    stationDb.station.update(
      {_id: station.id},
      {
        $set: {
          _class: "fdse.microservice.entity.Station",
          name: station.name,
          stayTime: station.stayTime
        }
      },
      {upsert: true}
    );
  });
  print("seeded station documents: " + stations.length);
}

function seedRoutes(routeDb, routeIds) {
  var seeded = [];
  routeDb.routes.remove({_id: {$regex: "^tf-", $nin: routeIds}});
  for (var number = 1345; number <= 1444; number += 1) {
    var idx = number - 1345;
    var pair = stationPair(number);
    var routeId = routeIds[idx];
    var distance = 80 + ((idx * 37) % 720);
    routeDb.routes.update(
      {_id: routeId},
      {
        $set: {
          _class: "route.entity.Route",
          stations: [pair.start.id, pair.terminal.id],
          distances: [0, distance],
          startStationId: pair.start.id,
          terminalStationId: pair.terminal.id
        }
      },
      {upsert: true}
    );
    seeded.push(routeId);
  }
  print("seeded routes: " + seeded[0] + "..." + seeded[seeded.length - 1] + " (" + seeded.length + ")");
}

function seedPrices(priceDb, routeIds) {
  var seeded = [];
  priceDb.price_config.remove({routeId: {$regex: "^tf-", $nin: routeIds}});
  for (var number = 1345; number <= 1444; number += 1) {
    var idx = number - 1345;
    var price = {
      id: "11111111-" + number + "-4000-8000-00000000" + number,
      trainType: trainTypes[idx % trainTypes.length],
      routeId: routeIds[idx],
      basicPriceRate: 0.45 + ((idx + 1) / 100.0)
    };
    priceDb.price_config.remove({
      trainType: price.trainType,
      routeId: price.routeId
    });
    priceDb.price_config.insert({
      _id: UUID(price.id),
      _class: "price.entity.PriceConfig",
      trainType: price.trainType,
      routeId: price.routeId,
      basicPriceRate: price.basicPriceRate,
      firstClassPriceRate: 1
    });
    seeded.push(price.routeId + "/" + price.trainType);
  }
  print("seeded price configs: " + seeded[0] + "..." + seeded[seeded.length - 1] + " (" + seeded.length + ")");
}

function seedTrips(travelDb) {
  var seeded = [];
  for (var number = 1345; number <= 1444; number += 1) {
    var minute = number - 1345;
    var pair = stationPair(number);
    var trip = {
      type: "D",
      number: String(number),
      trainTypeId: trainTypes[(number - 1345) % trainTypes.length],
      routeId: routeIdFor(number),
      start: new Date(Date.UTC(2013, 4, 4, Math.floor(minute / 60), minute % 60, 0)),
      end: new Date(Date.UTC(2013, 4, 4, 12 + Math.floor(minute / 60), minute % 60, 0))
    };
    travelDb.trip.update(
      {_id: {type: trip.type, number: trip.number}},
      {
        $set: {
          _class: "travel.entity.Trip",
          trainTypeId: trip.trainTypeId,
          routeId: trip.routeId,
          startingTime: trip.start,
          startingStationId: pair.start.id,
          stationsId: pair.terminal.id,
          terminalStationId: pair.terminal.id,
          endTime: trip.end
        }
      },
      {upsert: true}
    );
    seeded.push(trip.type + trip.number);
  }
  print("seeded trips: " + seeded[0] + "..." + seeded[seeded.length - 1] + " (" + seeded.length + ")");
}

var routeIds = activeRouteIds();
seedStations(serviceDb("ts-station-mongo"));
seedRoutes(serviceDb("ts-route-mongo"), routeIds);
seedPrices(serviceDb("ts-price-mongo"), routeIds);
seedTrips(serviceDb("ts-travel-mongo"));
print("seeded TrainTicket 20-station preserve benchmark data");
