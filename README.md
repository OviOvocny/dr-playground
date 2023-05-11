# DR Data Playground and Transformation Tools

With the data from domain collector, we can now start to play with it and transform it into a format that is suitable for training a model. This repository contains the tools to do that.

## Installation
As always, it is recommended to use a virtual environment. The following commands will create a virtual environment and install the requirements into it:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
If you use a different tool, such as `conda`, you can use that instead. Just make sure to install the requirements and use the correct python version. As of the versions fixed in the requirements file, SHAP requires numba, which only works with python up to version 3.10, which is recommended to use here. If you want to use a newer version of python, you can try removing the version pinning and see if it works.

Next, you need to create a `.env` file in the root of the repository. An example file is provided. Fill in the database connection string, otherwise the loader will default to a local unauthenticated instance. If you use different database name and collections, check the `config.py` file as well.

## Usage
The main entry point is the `loader.py` script. It will load the data from the database, apply the transformers and save the result to a file. The transformers are defined in the `transformers` directory. The `playground.ipynb` notebook contains some examples of how to use the data and train a model. Play with the notebooks or help extract data from the database. See also the README in the `transformers` directory for more information on how to write transformers. See the comments in `loader.py` for more information on how to run the loader and where to look next.

## Contributing
If you want to contribute, please open an issue or pull request. If you want to add a new transformer, please see the README in the `transformers` directory for more information on how to do that.