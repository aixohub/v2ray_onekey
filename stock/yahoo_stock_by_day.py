from yahoo_fin.stock_info import get_data

import pandas as pd

pd.set_option('display.max_rows', 5000)
pd.set_option('display.max_columns', 5000)
pd.set_option('display.width', 1000)
trade_path = '/Users/jupyter/workspace/sideproject/python/trader_qunant/a_share_data/day/'


def stock_us_day_data(stock_name, start_date, end_date):
    print("stock_name: " + stock_name + ",start_date:" + str(start_date) + ", end_date: " + str(end_date))
    amazon_weekly = get_data(stock_name, start_date=start_date, end_date=end_date, index_as_date=True, interval="1d")
    amazon_weekly.reset_index(inplace=True)
    amazon_weekly = amazon_weekly.rename(columns={'index': 'datatime'})
    amazon_weekly.to_csv(trade_path + 'trade_data_by_day_' + stock_name + '.csv', index=False, encoding='utf-8')


if __name__ == '__main__':
    stock_codes = {'JD', 'AAPL', 'AMZN', 'TSLA', 'BABA', 'MSFT', 'NVDA', 'OXY', 'META', 'googl'}
    for index, code in enumerate(stock_codes):
        stock_us_day_data(code, start_date="01/01/2020", end_date="12/31/2022")
