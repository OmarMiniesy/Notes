
### General Notes

> No need to wait for loading pages.
> Handled by the server.
> Giving users illusion of routing.
> One of the advantages of [[ReactJs]]

> Changing urls and what happens on the screen without calling new HTML pages.

> Create new directory called `pages` used in the same way as [[JavaScript/ReactJs/Components]] but will be used for routing. 

---

### Install Routing using [[Node Package Manager (NPM)]] and Setup

> `npm install react-router-dom`

> `index.js`
```JavaScript 
import { BrowserRouter } from 'react-router-dom';
---
.render(<BrowserRouter> <App /> </BrowserRouter>);
```

---

### Implementation: `Route` and `Switch` in `App.js`

> In the component that was wrapped, such as the `<App />` component here
> We need to import `Route` to be able to define differnet paths to listen to from the URL.
> We also need to import the different components that are going to be loaded and matched with the paths.
> The [[JavaScript/ReactJs/Components]] are then loaded.

>`App.js`
```JavaScript
import { Route, Switch } from 'react-router-dom';

import { comp1 } from './pages/comp1'

function App(){
return (
	<div>
	 <Switch> 
	 <Route path = '/' exact> <comp1 /> </Route>
	 </Switch>
	</div>
);
}
```
> What this does is that it checks the path, and once it finds the right path, it loads the components.
> If i remove the `Switch`, then it will load the components on top of one another, those that have matching parts of the path.
> The `Switch` helps to pick only 1, however, it will pick the first component that it sees with part of the path it has. To prevent this, add the `exact` attribute.
> The `exact` attribute helps to pick this path only if it matches it all.

> Adding stuff before the `switch` element will keep this stuff, and display the new pages *after* the stuff before the `switch`. 

---

### Implementation: `Link`

> To supersede the links done by `< a href>` so as to not send requests.
> In a component that has links, we need to include in it the `{ Link }` element.
> Then, we add a `<Link> </Link>` element that allows us to use the paths in React.
> Specify the path using the `to`  attribute.

``` JavaScript
<Link to='/<path>'> Page 1</Link>
```
> We can then include this component in the `App.js` file to serve as a linking component.

---
