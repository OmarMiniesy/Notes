
### General Notes

Content Delivery Network that speeds up delivery through _edge locations_.
- Data is cached at edge locations, and when user requests data, edge locations are first checked. 
- If data not present, then data is pulled from origin and cached there.

> Max size of single file is 20 GB

___
### Properties

- **Origins**: Choose the origin file, probably a [[Simple Storage Service (S3)]] bucket.
- **Restrictions**: block IPs from certain countries (GeoIP)
- **Invalidations**: Expire content from cache.

___

### CloudFront Distribution on [[Simple Storage Service (S3)]] Bucket

This is an example of a static website.

1. Create the bucket
2. Add files to bucket
3. ![config](./Pictures/cloudfrontdist.png)

3. [[Simple Storage Service (S3)]] bucket access policy will change 
4. Take domain name of the CloudFront distribution and add `/filename` and paste URL in browser.

___
