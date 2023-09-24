from typing import Optional

from xgboost import XGBClassifier
import pandas as pd
from sklearn.model_selection import GridSearchCV, StratifiedKFold, cross_val_score
from matplotlib import pyplot as plt

_default_params = {
    "max_depth": 9,
    "eta": 0.15,
    "objective": "binary:logistic",
    "min_child_weight": 2.0,
    "subsample": 0.6,
    "alpha": 0,
    "gamma": 0.1,
    "lambda": 1.0,
    "max_delta_step": 0,
    "grow_policy": "lossguide",
    "max_bin": 512,
    "tree_method": "gpu_hist",
    "sampling_method": "gradient_based"
}

_default_search_grid = {
    "max_depth": [9],
    "min_child_weight": [2],
    "sampling_method": ["uniform"],
    "subsample": [0.6],
    "gamma": [0.1],
    "grow_policy": ["lossguide"],
    "max_bin": [512],
    "n_estimators": [270, 280, 290],
    "lambda": [1.0],
    "alpha": [0.0]
}


def make_model(params: Optional[dict], n_estimators: int, use_gpu: Optional[bool] = False) -> XGBClassifier:
    if params is None:
        params = dict(_default_params)

    if use_gpu is not None and not use_gpu:
        params["tree_method"] = "hist"
        params["sampling_method"] = "uniform"

    return XGBClassifier(
        **params,
        n_estimators=n_estimators,
        eval_metric=["error", "logloss", "auc"]
    )


def cross_validate_model(model, X, y, n_splits=5, random_state=42):
    k_fold = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    results = cross_val_score(model, X, y, cv=k_fold, scoring='f1')
    print("Cross-validation F1: %.2f%% (stdev: %.2f%%)" % (results.mean() * 100, results.std() * 100))
    return results


def _plot_metric(results, x_axis, metric):
    plt.rcParams["figure.dpi"] = 300
    plt.plot(x_axis, results['validation_0'][metric], label='Training set')
    plt.plot(x_axis, results['validation_1'][metric], label='Testing set')
    plt.legend()
    mnames = {'error': 'Classification Error', 'logloss': 'Log Loss', 'auc': 'AUC'}
    mname = mnames[metric]
    plt.ylabel(mname)
    plt.xlabel('Number of trees')
    plt.title('XGBoost ' + mname)
    plt.show()


def plot_metrics(results):
    trees = len(results['validation_0']['error'])
    x_axis = range(0, trees)
    _plot_metric(results, x_axis, 'error')
    _plot_metric(results, x_axis, 'logloss')
    _plot_metric(results, x_axis, 'auc')


def find_optimal_model(X, y, grid=None, use_gpu: bool = True, n_splits=5, random_state=42):
    params = {
        "eta": 0.15,
        "objective": "binary:logistic",
        "tree_method": "gpu_hist" if use_gpu else "hist",
    }

    clf = XGBClassifier(**params)

    # this is your grid of parameters to search through, every combination will be tried
    if grid is None:
        grid = _default_search_grid
    if use_gpu:
        grid["sampling_method"] = ["gradient_based", "uniform"]

    cv = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    grid_search = GridSearchCV(
        estimator=clf,
        param_grid=grid,
        cv=cv,
        scoring='neg_log_loss',  # 'f1',
        verbose=3,
        return_train_score=True
    )

    grid_search.fit(X, y)

    scores = pd.DataFrame(grid_search.cv_results_)
    col_names = ['mean_train_score', 'mean_test_score']
    means_df = scores[col_names]
    ax = means_df.plot(kind='line', grid=True)

    plt.rcParams["figure.figsize"] = [12, 12]
    plt.rcParams["figure.autolayout"] = True
    plt.rcParams["figure.dpi"] = 300

    max_ids = means_df.idxmax(axis=0)

    for i in range(len(max_ids)):
        for col_name in col_names:
            value = means_df[col_name][max_ids[i]]
            id = max_ids[i]

            color = 'r' if max_ids[i] == max_ids['mean_test_score'] else 'grey'

            ax.scatter([id], [value],
                       marker='o',
                       color=color,
                       label='point', )

            ax.annotate(str(round(value, 3)) + "_ID=" + str(id),
                        (id, value),
                        xytext=(id + 3, value))

    return scores
