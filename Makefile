
run:
	docker build . -t template-nodejs
	docker run -p 3000:80 template-nodejs