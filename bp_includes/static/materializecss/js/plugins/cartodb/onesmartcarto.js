/*

	Non-carto methods through JQuery JSON overrides
	Useful when carto cache is causing issues.

*/
$.ajaxSetup({ cache: false });
// simple select
function ajaxSelect(cartodb_user,cartodb_table,csv_columns,sql_statement){
	$.getJSON('https://'+cartodb_user+'.carto.com/api/v2/sql/?q=SELECT '+csv_columns+' FROM '+cartodb_table+sql_statement, function(response) {
	  console.log(response);
	});
}
// simple update
function ajaxUpdate(cartodb_user,cartodb_table,sql_statement,csv_columns,csv_values,cartodb_apikey){
	$.getJSON('https://'+cartodb_user+'.carto.com/api/v2/sql/?q=UPDATE SET ('+csv_columns+') = ('+csv_values+') FROM '+cartodb_table+' '+sql_statement+'&api_key='+cartodb_apikey, function(response) {
	  console.log(response);
	});
}
// simple insert
function ajaxInsert(cartodb_user,cartodb_table,sql_statement,csv_columns,csv_values,cartodb_apikey){
	$.getJSON('https://'+cartodb_user+'.carto.com/api/v2/sql/?q=INSERT INTO '+cartodb_table+' ('+csv_columns+') VALUES ('+csv_values+')&api_key='+cartodb_apikey, function(response) {
	  console.log(response);
	});
}
// simple DELETE
function ajaxDelete(cartodb_user,cartodb_table,sql_statement,cartodb_apikey){
	$.getJSON('https://'+cartodb_user+'.carto.com/api/v2/sql/?q=DELETE FROM '+cartodb_table+' '+sql_statement+'&api_key='+cartodb_apikey, function(response) {
	  console.log(response);
	});
}

/*

	CARTO USEFUL METHODS & QUERIES

*/
function getFullQuery(cartodb_user,sql_statement){
	var sql = new cartodb.SQL({ user: cartodb_user });
	sql.execute(sql_statement)
    .done(function(response) {
        console.log('getFullQuery response', response);
        // YOUR CODE HERE
    });
}

function getLatLng(cartodb_user,cartodb_table,sql_statement){
	var sql = new cartodb.SQL({ user: cartodb_user });
	sql.execute("SELECT *, st_y(the_geom) as lat, st_x(the_geom) as lng FROM "+cartodb_table+" "+sql_statement)
    .done(function(response) {
        console.log('getLatLng response', response);
        // YOUR CODE HERE
        //var latlng = new google.maps.LatLng(response.rows[0].lat,response.rows[0].lng);
        //dropMarker (latlng);
    });
}

function triggerInfowindow(cartodb_user,cartodb_table,sql_statement,sublayer){
	var sql = new cartodb.SQL({ user: cartodb_user });
	sql.execute("SELECT *, ST_AsText(ST_Centroid(the_geom)) FROM "+cartodb_table+" "+sql_statement)
    .done(function(response) {
        console.log('triggerInfowindow response', response);
        var x = parseFloat(response.rows[0].st_astext.replace('POINT(','').split(' ')[0]);
        var y = parseFloat(response.rows[0].st_astext.replace('POINT(','').split(' ')[1]);
        sublayer.trigger('featureClick', null, [y, x], null, { cartodb_id: response.rows[0].cartodb_id }, 0);
    });
}

function getIntersectFromDrawing(cartodb_user,cartodb_table,geom_text){
	var sql = new cartodb.SQL({ user: cartodb_user });
	sql.execute("SELECT * FROM "+cartodb_table+" WHERE ST_Intersects(the_geom, ST_GeomFromText('"+geom_text+"',4326))")
    .done(function(response) {
        console.log('getIntersectFromDrawing response', response);
        // YOUR CODE HERE
    });
}

function getIntersectFromBufferedDrawing(cartodb_user,cartodb_table,geom_text,buffer_in_meters){
	var sql = new cartodb.SQL({ user: cartodb_user });
	sql.execute("SELECT * FROM "+cartodb_table+" WHERE ST_DWithin(ST_Transform(ST_GeomFromText('"+geom_text+"',4326), 2163), ST_Transform(the_geom, 2163), " + buffer_in_meters + ")")
    .done(function(response) {
        console.log('getIntersectFromBufferedDrawing response', response);
        // YOUR CODE HERE
    });
}

function getArea(cartodb_user,cartodb_table,sql_statement){
	var sql = new cartodb.SQL({ user: cartodb_user });
	sql.execute("SELECT ST_Area(the_geom::geography) as sqm, ST_Area(the_geom::geography)/1000000 as sqkm, ST_Area(the_geom::geography)*10.7639 as sqft FROM "+cartodb_table+" "+sql_statement)
    .done(function(response) {
        console.log('getArea response', response);
        // YOUR CODE HERE
    });
}

function getAreaFromDrawing(cartodb_user,geom_text){
	var sql = new cartodb.SQL({ user: cartodb_user });
	sql.execute("WITH elem AS (SELECT ST_Transform(ST_GeomFromText('"+geom_text+"', 4326), 2163) as the_geom) SELECT ST_Area(the_geom) as sqm, ST_Area(the_geom)/1000000 as sqkm, ST_Area(the_geom)*10.7639 as sqft FROM elem")
    .done(function(response) {
        console.log('getAreaFromDrawing response', response);
        // YOUR CODE HERE
    });
}

function getDistanceFromDrawing(cartodb_user,cartodb_table,sql_statement,geom_text){
	var sql = new cartodb.SQL({ user: cartodb_user });
	sql.execute("SELECT ST_Distance(ST_GeomFromText('"+geom_text+"', 4326), the_geom) as degrees, ST_Distance(ST_Transform(ST_GeomFromText('"+geom_text+"', 4326), 2163), ST_Transform(the_geom, 2163)) as m, ST_Distance(ST_Transform(ST_GeomFromText('"+geom_text+"', 4326), 2163), ST_Transform(the_geom, 2163))/1000 as km FROM "+cartodb_table+" "+sql_statement)
    .done(function(response) {
        console.log('getDistanceBetweenDrawings response', response);
        // YOUR CODE HERE
    });
}

function getDistanceBetweenDrawings(cartodb_user,geom_text_1,geom_text_2){
	var sql = new cartodb.SQL({ user: cartodb_user });
	sql.execute("SELECT ST_Distance(ST_GeomFromText('"+geom_text_1+"', 4326), ST_GeomFromText('"+geom_text_2+"', 4326)) as degrees, ST_Distance(ST_Transform(ST_GeomFromText('"+geom_text_1+"', 4326), 2163), ST_Transform(ST_GeomFromText('"+geom_text_2+"', 4326), 2163)) as m, ST_Distance(ST_Transform(ST_GeomFromText('"+geom_text_1+"', 4326), 2163), ST_Transform(ST_GeomFromText('"+geom_text_2+"', 4326), 2163))/1000 as km")
    .done(function(response) {
        console.log('getDistanceBetweenDrawings response', response);
        // YOUR CODE HERE
    });
}

function getDrawingFromGeom(cartodb_user,cartodb_table,sql_statement){
	var sql = new cartodb.SQL({ user: cartodb_user });
	sql.execute("SELECT ST_AsText(the_geom) FROM "+cartodb_table+" "+sql_statement)
    .done(function(response) {
        console.log('getDrawingFromGeom response', response);
        // YOUR CODE HERE
    });
}

/*
	USEFUL SQL STATEMENTS

	(1) GET SCHEMA (needs to be in carto console)
		
		SELECT column_name FROM information_schema.columns WHERE table_name = 'YOUR_TABLE'

	(2) INSERT AN ELEMENT (need api_key parameter)

		INSERT INTO table (col1,col2,col3) VALUES ('a',2,'c')

	(3) UPDATE AN ELEMENT (need api_key parameter)

		UPDATE SET (col1,col2,col3) = ('A',100,'C') FROM table WHERE cartodb_id = 1

	(4) DELETE AN ELEMENT (need api_key parameter)

		DELETE FROM table WHERE cartodb_id = 1


	(5) INTERSECTION

		from tables: 	

			SELECT table_1.* FROM table_1, table_2 WHERE ST_Intersects(table_1.the_geom, table_2.the_geom)

		from a GEOM TEXT:

			SELECT * FROM table WHERE ST_Intersects(the_geom, ST_GeomFromText('POLYGON((-100.3047801554203 25.709135581044972,-100.30812755227089 25.70364473148278,-100.30134692788124 25.70364473148278,-100.3047801554203 25.709135581044972))',4326))

		from a GEOM (useful for querying intersections among different carto accounts):

			query for the_geom in one carto user, then query second user as:

			SELECT * FROM table WHERE ST_Intersects(the_geom, ST_GeomFromText(ST_AsText('"+previous.the_geom+"'),4326))



	(6) INTERSECTIONS 

		WITHIN 
		
			use a distance in meters (e.g. 25):

				SELECT table_1.* FROM table_1, table_2 WHERE ST_DWithin(ST_Transform(table_1.the_geom, 2163), ST_Transform(table_2.the_geom, 2163), 25)

			using meters (e.g. 25) from GEOM TEXT element:

				SELECT * FROM table WHERE ST_DWithin(ST_Transform(ST_GeomFromText('POINT(-100.31464064550778 25.720455131035184)', 4326), 2163), ST_Transform(table.the_geom, 2163), 25)

	
		BUFFER

			use an earth radius calculated as:

				// dist is the distance in meters
				function updateEarthRadius(lat, lng, dist) {
				    var deg = 180,
				        brng = deg * Math.PI / 180,
				        dist = dist / 6371000,
				        lat1 = lat * Math.PI / 180,
				        lon1 = lng * Math.PI / 180, radius;

				    var lat2 = Math.asin(Math.sin(lat1) * Math.cos(dist) + Math.cos(lat1) * Math.sin(dist) * Math.cos(brng));

				    var lon2 = lon1 + Math.atan2(Math.sin(brng) * Math.sin(dist) * Math.cos(lat1), Math.cos(dist) - Math.sin(lat1) * Math.sin(lat2));

				    if (isNaN(lat2) || isNaN(lon2)) radius = null;

				    else radius = lat - (lat2 * 180 / Math.PI);

				    return radius
				}

				SELECT * FROM table WHERE ( ST_Intersects(table.the_geom,ST_Buffer( ST_SetSRID('POINT(-100.31464064550778 25.720455131035184)'::geometry , 4326),0.04496608029593929)))

			using meters (e.g. 25):

				SELECT * FROM table WHERE ST_Intersects(ST_Buffer(ST_Transform(ST_GeomFromText('POINT(-100.31464064550778 25.720455131035184)', 4326), 2163), 25), ST_Transform(table.the_geom, 2163))


	(8) DATES

		intervals: 		

			SELECT * FROM table WHERE (((now()) - table.date_field) < INTERVAL '7 day')

			SELECT * FROM table WHERE (((now()) - table.date_field) < INTERVAL '7 hour')
		
		betweens: 	

			SELECT * FROM table WHERE ((table.date_field BETWEEN ('2016-12-09') AND (DATE '2016-12-09' + 1)))

			SELECT * FROM table WHERE ((date_part('hour', table.date_field) BETWEEN 8 AND 15))

		days of week: 	

			SELECT * FROM table WHERE EXTRACT(dow FROM table.date_field) IN (1 , 3 , 5)


	(9) DISTANCE

		from a GEOM TEXT in a given range (e.g. 25 meters):

			SELECT * FROM table where ST_Distance(ST_Transform(table.the_geom, 2163), ST_Transform(ST_GeomFromText('POINT(-100.31464064550778 25.720455131035184)', 4326), 2163)) < 25

			how about using ST_DWithin ?

			SELECT * FROM table where ST_DWithin(ST_Transform(table.the_geom, 2163), ST_Transform(ST_GeomFromText('POINT(-100.31464064550778 25.720455131035184)', 4326), 2163), 25)

		get distance only

			SELECT ST_Distance(ST_GeomFromText('"+geom_text_1+"', 4326), ST_GeomFromText('"+geom_text_2+"', 4326)) as degrees, ST_Distance(ST_Transform(ST_GeomFromText('"+geom_text_1+"', 4326), 2163), ST_Transform(ST_GeomFromText('"+geom_text_2+"', 4326), 2163)) as m, ST_Distance(ST_Transform(ST_GeomFromText('"+geom_text_1+"', 4326), 2163), ST_Transform(ST_GeomFromText('"+geom_text_2+"', 4326), 2163))/1000 as km

	(10) AREA

		SELECT ST_Area(the_geom::geography) as sqm, ST_Area(the_geom::geography)/1000000 as sqkm, ST_Area(the_geom::geography)*10.7639 as sqft FROM table

	(11) MERGING MULTIPLE POLYGONS INTO SINGLE GEOMETRY

		SELECT name, ST_Multi(ST_Collect(f.the_geom)) as singlegeom FROM (SELECT name, (ST_Dump(the_geom)).geom As the_geom FROM table ) As f GROUP BY name
	
	= = = 

	NOTES

		POSTGIS PROJECTIONS ARE BASED ON SRIDs SUCH AS:
			4326, WGS 84, UNITS IN PLANAR DEGREES [GEOMetry] (CARTO DEFAULT)
			2163, US NATIONAL ATLAS, UNITS IN METERS [GEOGraphy] (easiest appreciation as it is in meters)


*/

console.log('onesmartcarto.js 0.0.1');

