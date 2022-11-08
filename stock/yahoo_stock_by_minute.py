from datetime import datetime, timedelta, date

from yahoo_fin.stock_info import get_data

import pandas as pd

pd.set_option('display.max_rows', 5000)
pd.set_option('display.max_columns', 5000)
pd.set_option('display.width', 1000)
trade_path = '/Users/jupyter/workspace/sideproject/python/trader_qunant/a_share_data/minute/'


def stock_us_day_data(stock_name, start_date, end_date):
    print("stock_name: " + stock_name + ",start_date:" + str(start_date) + ", end_date: " + str(end_date))
    amazon_weekly = get_data(stock_name, start_date=start_date, end_date=end_date, index_as_date=True, interval="1m")
    amazon_weekly.dropna(
        axis=0,
        how='any',
        subset=None,
        inplace=True
    )
    amazon_weekly.reset_index(inplace=True)
    amazon_weekly = amazon_weekly.rename(columns={'index': 'datatime'})
    amazon_weekly = amazon_weekly.drop(columns=['ticker'], axis=1)
    amazon_weekly = amazon_weekly.drop(index=amazon_weekly.volume[amazon_weekly.volume == 0].index)
    amazon_weekly.to_csv(trade_path + 'trade_data_by_minute_' + stock_name + '.csv', mode="a", index=False,
                         encoding='utf-8', header=False)


if __name__ == '__main__':
    """
    start_date = "01/01/2020"
    end_date = "12/31/2022"
    """
    stock_codes = {'JD', 'AAPL', 'AMZN', 'TSLA', 'BABA', 'MSFT', 'NVDA', 'OXY', 'META', 'googl'}

    start_date = "10/15/2022"
    start_date_time = datetime.strptime(start_date, "%m/%d/%Y")

    end_date_time = datetime.today()

    for code in stock_codes:
        data_init = start_date_time
        date_2 = start_date_time + timedelta(days=5)
        while date_2 < end_date_time:
            date_2 = data_init + timedelta(days=7)
            stock_us_day_data(code, data_init, date_2)
            data_init = date_2
